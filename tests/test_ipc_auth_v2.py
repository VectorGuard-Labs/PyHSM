"""Version-2 IPC authentication, replay protection, peer identity, and safe errors.

Each test is an attack that worked against version 1 (where the token covered only the request id
and the operation), or a leak the old error handling allowed.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import tempfile
import threading
import time
import uuid
from pathlib import Path

import pytest

from hsm.ipc_auth import (
    SAFE_ERRORS,
    ReplayCache,
    Verifier,
    attributed_caller,
    canonical_body,
    classify_error,
    peer_identity,
    sign_request,
)
from hsm.ipc_client import IPCClient, RateLimitedError
from hsm.ipc_server import IPCServer

_SECRET = "v2-test-secret-" + "x" * 32
_PW = "Str0ng!TestPassphrase#2026"
_HEADER = struct.Struct(">I")


def _server(tmp_path: Path, **kw):
    sock_dir = tempfile.mkdtemp(prefix="pyhsm2_", dir="/tmp")
    path = os.path.join(sock_dir, "p.sock")
    srv = IPCServer(
        store_path=str(tmp_path / "ks.enc"), socket_path=path, master_password=_PW,
        ipc_secret=_SECRET, session_timeout_s=0, conn_timeout_s=3.0, **kw,
    )
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if os.path.exists(path):
            break
        time.sleep(0.05)
    return srv, path


def _conn(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(path)
    return s


def _send(s, payload):
    data = json.dumps(payload).encode()
    s.sendall(_HEADER.pack(len(data)) + data)


def _recv(s):
    head = b""
    while len(head) < 4:
        chunk = s.recv(4 - len(head))
        if not chunk:
            return None
        head += chunk
    (n,) = _HEADER.unpack(head)
    body = b""
    while len(body) < n:
        body += s.recv(n - len(body))
    return json.loads(body)


def _call(path, payload):
    s = _conn(path)
    try:
        _send(s, payload)
        return _recv(s)
    finally:
        s.close()


def _signed(op, **fields):
    return sign_request(_SECRET.encode(), {"type": op, "request_id": str(uuid.uuid4()), "caller_id": "test", **fields})


@pytest.fixture()
def server(tmp_path):
    srv, path = _server(tmp_path)
    yield srv, path
    srv._shutdown.set()


# ---- the signature covers the whole request ---------------------------------------------

def test_a_genuine_signed_request_is_accepted(server):
    _, path = server
    assert _call(path, _signed("health"))["ok"] is True


def test_an_exact_replay_is_refused(server):
    """The attack version 1 allowed: capture a request and send it again, unchanged."""
    _, path = server
    req = _signed("health")
    assert _call(path, req)["ok"] is True
    again = _call(path, req)
    assert again["ok"] is False and again.get("code") == "auth_failed"


def test_changing_any_parameter_breaks_the_signature(server):
    """The other version-1 gap: keep the token, change the key or the ciphertext."""
    srv, path = server
    assert _call(path, _signed("generate_key", key_id="k1", key_type="aes-256"))["ok"] is True
    good = _signed("encrypt", key_id="k1", plaintext="hello")
    for field, value in [("key_id", "k2"), ("plaintext", "goodbye"), ("type", "decrypt"), ("caller_id", "admin"), ("ts", good["ts"] + 1)]:
        tampered = dict(good, **{field: value})
        tampered["request_id"] = str(uuid.uuid4()) if field != "type" else good["request_id"]
        # (a fresh id so the replay check is not what stops it)
        tampered = dict(tampered, request_id=str(uuid.uuid4()))
        r = _call(path, tampered)
        assert r["ok"] is False and r.get("code") == "auth_failed", field
    # adding a field also breaks it
    extra = dict(good, request_id=str(uuid.uuid4()), backup_dir="/tmp/x")
    assert _call(path, extra)["ok"] is False
    assert _call(path, good)["ok"] is True, "the untouched request is still fine"


def test_stale_and_future_timestamps_are_refused(server):
    _, path = server
    for skew in (-3600, -61, 61, 3600):
        req = sign_request(_SECRET.encode(), {"type": "health", "request_id": str(uuid.uuid4()), "ts": int(time.time()) + skew})
        assert _call(path, req)["ok"] is False, skew
    near = sign_request(_SECRET.encode(), {"type": "health", "request_id": str(uuid.uuid4()), "ts": int(time.time()) - 30})
    assert _call(path, near)["ok"] is True


def test_malformed_auth_fields_are_refused(server):
    _, path = server
    base = _signed("health")
    for bad in [
        dict(base, ts="not a number"),
        dict(base, ts=True),
        dict(base, request_id="x"),             # too short to be an id
        dict(base, request_id="../../etc"),     # not an id
        {k: v for k, v in base.items() if k != "auth"},
        dict(base, auth=""),
    ]:
        r = _call(path, bad)
        assert r is None or r["ok"] is False


def test_version_1_tokens_are_refused_by_default(server):
    _, path = server
    import hmac
    rid = str(uuid.uuid4())
    v1 = hmac.new(_SECRET.encode(), f"{rid}:health".encode(), hashlib.sha256).hexdigest()
    r = _call(path, {"type": "health", "request_id": rid, "auth": v1})
    assert r["ok"] is False and r.get("code") == "auth_failed"


def test_version_1_can_be_allowed_for_migration_and_is_still_replay_protected(tmp_path):
    import hmac
    srv, path = _server(tmp_path, allow_legacy_auth=True)
    try:
        rid = str(uuid.uuid4())
        v1 = {"type": "health", "request_id": rid, "auth": hmac.new(_SECRET.encode(), f"{rid}:health".encode(), hashlib.sha256).hexdigest()}
        assert _call(path, v1)["ok"] is True
        assert _call(path, v1)["ok"] is False, "replayed even in legacy mode"
    finally:
        srv._shutdown.set()


def test_the_python_client_speaks_version_2(server):
    _, path = server
    with IPCClient(path, ipc_secret=_SECRET) as c:
        assert c.health()["status"] == "ok"
        c.generate_key("k", "aes-256")
        assert c.decrypt("k", c.encrypt("k", "round trip")) in ("round trip", b"round trip")


# ---- canonical body: a fixed vector other-language clients must reproduce ---------------

def test_the_canonical_body_is_stable_and_matches_the_published_vector():
    req = {"type": "encrypt", "request_id": "11111111-2222-3333-4444-555555555555", "caller_id": "vectorscrub-backend",
           "key_id": "vectorscrub-kek", "plaintext": "aGVsbG8=", "ts": 1700000000, "auth_v": 2, "auth": "ignored"}
    body = canonical_body(req)
    assert body == (b'{"caller_id":"vectorscrub-backend","key_id":"vectorscrub-kek","plaintext":"aGVsbG8=",'
                    b'"request_id":"11111111-2222-3333-4444-555555555555","ts":1700000000,"type":"encrypt"}')
    signed = sign_request(b"s" * 40, {k: v for k, v in req.items() if k not in ("auth", "auth_v")})
    # Frozen: VectorScrub's Rust client asserts the same value (services/keys.rs).
    assert signed["auth"] == "7843691e60a22a195d460667947ecb6f5dc1181f3db6fa6c0e78f781b2a574ca"
    assert canonical_body({"type": "x", "request_id": "r", "s": "é\n\u001b"}) == '{"request_id":"r","s":"é\\n\\u001b","type":"x"}'.encode()


# ---- replay cache -----------------------------------------------------------------------

def test_the_replay_cache_forgets_old_ids_and_fails_closed_when_full():
    c = ReplayCache(window_s=10, max_entries=3)
    assert c.add("a", 0) and not c.add("a", 1)
    assert c.add("b", 1) and c.add("c", 2)
    assert not c.add("d", 3), "full: refuse rather than forget an id that could still be replayed"
    assert c.add("d", 11), "once 'a' is out of the window there is room again"
    assert len(c) <= 3


def test_forged_requests_cannot_fill_the_replay_cache():
    v = Verifier(_SECRET.encode())
    for _ in range(100):
        bad = sign_request(b"wrong-secret", {"type": "health", "request_id": str(uuid.uuid4())})
        assert v.verify(bad)[0] is False
    assert len(v._replay) == 0


# ---- who is connecting --------------------------------------------------------------------

def test_the_peer_is_identified_by_the_kernel():
    path = os.path.join(tempfile.mkdtemp(prefix="peer_", dir="/tmp"), "s")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)
    cli = socket.socket(socket.AF_UNIX)
    cli.connect(path)
    conn, _ = srv.accept()
    try:
        p = peer_identity(conn)
        assert p.uid == os.getuid()
        assert p.pid == os.getpid()
    finally:
        conn.close(); cli.close(); srv.close()


def test_a_user_not_on_the_allow_list_is_refused_before_any_request(tmp_path):
    srv, path = _server(tmp_path, allowed_uids={os.getuid() + 12345})
    try:
        r = _call(path, _signed("health"))
        assert r is None, "the connection is closed without an answer"
    finally:
        srv._shutdown.set()


def test_the_audit_caller_records_the_kernel_identity_not_just_the_claimed_name():
    class P:  # minimal stand-in for PeerIdentity
        uid, gid, pid = 1000, 1000, 42

        def label(self):
            return "uid=1000,pid=42"

    assert attributed_caller("vectorscrub-backend", P()) == "vectorscrub-backend(uid=1000,pid=42)"
    assert attributed_caller("admin(uid=0,pid=1)", P()) == "adminuid0pid1(uid=1000,pid=42)", "cannot fake the kernel part"
    assert attributed_caller("x" * 500, P()).startswith("x" * 64 + "(")
    assert attributed_caller(None, P()) == "ipc-client(uid=1000,pid=42)"


def test_the_audit_log_names_the_real_uid(server):
    srv, path = server
    assert _call(path, _signed("generate_key", key_id="audited", key_type="aes-256", caller_id="claims-to-be-root"))["ok"]
    with open(srv._hsm.get_audit_log().log_path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    mine = [e for e in entries if e.get("keyId") == "audited" or e.get("key_id") == "audited"]
    assert mine, "the operation was audited"
    caller = str(mine[-1].get("callerId"))
    assert caller == f"claims-to-be-root(uid={os.getuid()},pid={os.getpid()})", caller


# ---- errors that are safe to send ---------------------------------------------------------

def test_errors_are_fixed_messages_with_a_code_and_leak_nothing(server):
    _, path = server
    cases = [
        (_signed("encrypt", key_id="no-such-key-SECRETNAME", plaintext="x"), "not_found"),
        (_signed("encrypt"), "invalid_request"),                     # missing fields
        (_signed("verify_backup", backup_path="/Users/someone/secret/path.enc"), "not_found"),
    ]
    for req, code in cases:
        r = _call(path, req)
        assert r["ok"] is False and r["code"] == code, r
        assert r["error"] == SAFE_ERRORS[code]
        for leak in ("SECRETNAME", "/Users/", "/home/", "Traceback", "File \"", "keystore"):
            assert leak not in r["error"], (leak, r)


def test_decryption_failure_is_reported_as_such_without_details(server):
    _, path = server
    assert _call(path, _signed("generate_key", key_id="d", key_type="aes-256"))["ok"]
    ct = _call(path, _signed("encrypt", key_id="d", plaintext="x"))["data"]
    broken = ct[:-4] + ("0000" if not ct.endswith("0000") else "1111")
    r = _call(path, _signed("decrypt", key_id="d", ciphertext=broken))
    assert r["ok"] is False and r["code"] == "decrypt_failed" and r["error"] == SAFE_ERRORS["decrypt_failed"]


def test_the_rate_limit_has_its_own_code_and_the_client_raises_a_specific_error(tmp_path):
    srv, path = _server(tmp_path, rate_limit_max_ops=3)
    try:
        with IPCClient(path, ipc_secret=_SECRET) as c:
            c.generate_key("rl", "aes-256")
            with pytest.raises(RateLimitedError):
                for _ in range(10):
                    c.encrypt("rl", "x")
        r = _call(path, _signed("encrypt", key_id="rl", plaintext="x"))
        assert r["code"] == "rate_limited" and "rate-limited" in r["error"]
    finally:
        srv._shutdown.set()


def test_error_classification():
    assert classify_error(ValueError("PyHSM: key 'k' is rate-limited")) == "rate_limited"
    assert classify_error(ValueError("PyHSM: key 'k' policy denies decrypt")) == "policy_denied"
    assert classify_error(ValueError("PyHSM: key 'k' has expired")) == "policy_denied"
    assert classify_error(KeyError("Key 'k' not found")) == "not_found"
    assert classify_error(KeyError("key_id")) == "invalid_request"
    assert classify_error(FileNotFoundError("PyHSM: backup file not found: /x")) == "not_found"
    assert classify_error(ValueError("PyHSM: ciphertext too short")) == "decrypt_failed"
    assert classify_error(ValueError("anything else")) == "invalid_request"
    assert classify_error(RuntimeError("boom")) == "internal"
    from cryptography.exceptions import InvalidTag
    assert classify_error(InvalidTag()) == "decrypt_failed"
