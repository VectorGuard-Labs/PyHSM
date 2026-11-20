"""Container health check for the PyHSM IPC server.

Exit 0 when the server answers an authenticated `health` request on its socket, 1 otherwise.
The server requires every request to be authenticated, so this reads the same IPC secret the
server uses (PYHSM_IPC_SECRET, or the file named by PYHSM_IPC_SECRET_FILE). Without it the
check could only ever fail. Prints the error type only, never the secret or a path.
"""
import os
import sys

from hsm.ipc_client import IPCClient


def _secret():
    value = os.environ.get("PYHSM_IPC_SECRET")
    if value:
        return value
    path = os.environ.get("PYHSM_IPC_SECRET_FILE")
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return None


def main() -> int:
    socket_path = os.environ.get("PYHSM_SOCKET", "/run/pyhsm/pyhsm.sock")
    try:
        with IPCClient(socket_path, ipc_secret=_secret(), caller_id="healthcheck", timeout=4.0) as c:
            return 0 if c.health().get("status") == "ok" else 1
    except Exception as exc:  # any failure means "not healthy"
        print(f"unhealthy: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
