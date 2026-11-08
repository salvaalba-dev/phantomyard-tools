"""Local agent client for the existing PhantomView private handoff protocol.

The operator supplies the socket, reader account, scope and tool-owned signing
key from protected configuration. This module does not load secrets, send a
chat message, create a listener, or authenticate a remote human.
"""

import json
import re
import socket
import struct
import time
from pathlib import Path

from phantomdocs.view_agent_signing import sign_viewer_request


def _read(connection, size, deadline):
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Viewer response deadline exceeded")
        connection.settimeout(remaining)
        part = connection.recv(size - len(data))
        if not part:
            raise ValueError("Incomplete viewer response")
        data.extend(part)
    return bytes(data)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate viewer response field")
        result[key] = value
    return result


def request_agent_link(*, secret, origin, scope_id, socket_path, reader_uid):
    """Request one scoped link through an account-bound local reader socket."""
    if (not hasattr(socket, "SO_PEERCRED") or type(reader_uid) is not int or reader_uid <= 0
            or not isinstance(scope_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", scope_id)
            or not isinstance(socket_path, str) or not Path(socket_path).is_absolute()
            or ".." in Path(socket_path).parts or len(socket_path.encode()) > 100):
        raise ValueError("Fixed local viewer configuration required")
    path = Path(socket_path)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Linked viewer socket path is not allowed")
    authorization = sign_viewer_request(secret, origin)
    body = {"schema_version": 1, "authorization": authorization, "channel": "telegram",
            "sender": "agent", "direct": True, "principal_authenticated": True, "scope_id": scope_id}
    raw = json.dumps(body, separators=(",", ":")).encode()
    if len(raw) > 16384:
        raise ValueError("Viewer request exceeds bounds")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(socket_path)
        pid, uid, _gid = struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if pid <= 0 or uid != reader_uid:
            raise ValueError("Unexpected local viewer account")
        connection.sendall(struct.pack("!I", len(raw)) + raw)
        deadline = time.monotonic() + 3
        size = struct.unpack("!I", _read(connection, 4, deadline))[0]
        if not 0 < size <= 16384:
            raise ValueError("Invalid viewer response size")
        result = json.loads(_read(connection, size, deadline), object_pairs_hook=_unique)
    if (not isinstance(result, dict) or set(result) != {"schema_version", "link"}
            or type(result["schema_version"]) is not int or result["schema_version"] != 1
            or not isinstance(result["link"], str)
            or not re.fullmatch(re.escape(origin) + r"/#c=[A-Za-z0-9_-]{43}", result["link"])):
        raise ValueError("Viewer did not issue a valid link")
    return result["link"]
