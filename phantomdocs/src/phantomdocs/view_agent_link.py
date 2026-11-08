"""Local agent client for the existing PhantomView private handoff protocol.

The operator supplies the socket, reader account, scope and tool-owned signing
key from protected configuration. It does not send a chat message, create a
listener, or authenticate a remote human.
"""

import argparse
import json
import os
import re
import socket
import stat
import struct
import time
from pathlib import Path

from phantomdocs.view_agent_directory import ACTOR_SCOPE
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
    if (
        not hasattr(socket, "SO_PEERCRED")
        or type(reader_uid) is not int
        or reader_uid <= 0
        or not isinstance(scope_id, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", scope_id)
        or not isinstance(socket_path, str)
        or not Path(socket_path).is_absolute()
        or ".." in Path(socket_path).parts
        or len(socket_path.encode()) > 100
    ):
        raise ValueError("Fixed local viewer configuration required")
    path = Path(socket_path)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Linked viewer socket path is not allowed")
    authorization = sign_viewer_request(secret, origin)
    body = {
        "schema_version": 1,
        "authorization": authorization,
        "channel": "telegram",
        "sender": "agent",
        "direct": True,
        "principal_authenticated": True,
        "scope_id": scope_id,
    }
    raw = json.dumps(body, separators=(",", ":")).encode()
    if len(raw) > 16384:
        raise ValueError("Viewer request exceeds bounds")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(socket_path)
        pid, uid, _gid = struct.unpack(
            "3i",
            connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            ),
        )
        if pid <= 0 or uid != reader_uid:
            raise ValueError("Unexpected local viewer account")
        connection.sendall(struct.pack("!I", len(raw)) + raw)
        deadline = time.monotonic() + 3
        size = struct.unpack("!I", _read(connection, 4, deadline))[0]
        if not 0 < size <= 16384:
            raise ValueError("Invalid viewer response size")
        result = json.loads(
            _read(connection, size, deadline), object_pairs_hook=_unique
        )
    if (
        not isinstance(result, dict)
        or set(result) != {"schema_version", "link"}
        or type(result["schema_version"]) is not int
        or result["schema_version"] != 1
        or not isinstance(result["link"], str)
        or not re.fullmatch(
            re.escape(origin) + r"/#c=[A-Za-z0-9_-]{43}", result["link"]
        )
    ):
        raise ValueError("Viewer did not issue a valid link")
    return result["link"]


def _read_fixed_file(path, *, owner, mode_mask, limit):
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or ".." in Path(path).parts
    ):
        raise ValueError("Fixed local file required")
    target = Path(path)
    if target.is_symlink() or any(parent.is_symlink() for parent in target.parents):
        raise ValueError("Linked local files are not allowed")
    for parent in target.parents:
        info = parent.stat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, owner}
            or info.st_mode & 0o022
        ):
            raise ValueError("Unsafe local parent directory")
    fd = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner
            or info.st_nlink != 1
            or info.st_mode & mode_mask
        ):
            raise ValueError("Unsafe local file ownership or permissions")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("Local file exceeds bounds")
        return raw


def main():
    """Run under the agent account using a root-owned route configuration."""
    parser = argparse.ArgumentParser(description="Request a scoped PhantomView link")
    parser.add_argument("--config", required=True)
    parser.add_argument("--scope", default=ACTOR_SCOPE)
    args = parser.parse_args()
    try:
        if os.name != "posix" or os.getuid() <= 0:
            raise ValueError("An agent account is required")
        raw = _read_fixed_file(args.config, owner=0, mode_mask=0o022, limit=4096)
        config = json.loads(raw, object_pairs_hook=_unique)
        if (
            not isinstance(config, dict)
            or set(config)
            != {
                "schema_version",
                "agent_uid",
                "reader_uid",
                "origin",
                "socket_path",
                "key_path",
            }
            or type(config["schema_version"]) is not int
            or config["schema_version"] != 1
            or type(config["agent_uid"]) is not int
            or config["agent_uid"] != os.getuid()
        ):
            raise ValueError("Invalid protected agent route")
        key = _read_fixed_file(
            config["key_path"], owner=config["agent_uid"], mode_mask=0o077, limit=32
        )
        link = request_agent_link(
            secret=key,
            origin=config["origin"],
            scope_id=args.scope,
            socket_path=config["socket_path"],
            reader_uid=config["reader_uid"],
        )
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        raise SystemExit("PhantomView link unavailable") from None
    print(link)


if __name__ == "__main__":
    main()
