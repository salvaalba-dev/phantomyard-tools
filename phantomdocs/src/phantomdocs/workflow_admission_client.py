"""Experimental local peer client; it is not wired into the installed CLI.

The socket path and expected server UID must come from trusted configuration.
The server authenticates the client's kernel identity and applies PhantomOrg
authorization; this client does not turn a remote human into a local actor.
"""

import json
import os
import socket
import struct
import sys

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 4096
MAX_SEARCH_RESPONSE_BYTES = 128 * 1024
STATUSES = {
    "job": {"received", "blocked", "rejected"},
    "archive": {"indexed", "rejected"},
    "search": {"ok", "rejected"},
}


class PeerClientError(Exception):
    """The peer service could not be reached or did not answer safely."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


def request_peer(socket_path, expected_server_uid, request, *, timeout=5):
    """Submit one protocol request only after checking the server's real UID.

    The server UID and socket path must not be selected by an untrusted job.
    An error after sending is an uncertain outcome: callers must reconcile it,
    not assume failure or retry a write automatically.
    """
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise PeerClientError("peer service requires Linux")
    if (
        not isinstance(socket_path, str)
        or not os.path.isabs(socket_path)
        or "\x00" in socket_path
        or type(expected_server_uid) is not int
        or expected_server_uid < 0
        or not isinstance(request, dict)
        or set(request) not in ({"job"}, {"archive"}, {"search"})
    ):
        raise PeerClientError("invalid peer service configuration or request")
    try:
        raw = json.dumps(
            request, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (ValueError, TypeError, RecursionError) as exc:
        raise PeerClientError("invalid peer request") from exc
    if len(raw) > MAX_REQUEST_BYTES:
        raise PeerClientError("peer request exceeds limit")
    max_response = (
        MAX_SEARCH_RESPONSE_BYTES if "search" in request else MAX_RESPONSE_BYTES
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(socket_path)
            peer = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, _gid = struct.unpack("3i", peer)
            if pid <= 0 or uid != expected_server_uid:
                raise PeerClientError("untrusted peer service")
            connection.sendall(raw + b"\n")
            response = bytearray()
            while b"\n" not in response:
                part = connection.recv(min(4096, max_response + 2 - len(response)))
                if not part:
                    raise PeerClientError("peer outcome requires reconciliation")
                response.extend(part)
                if len(response) > max_response + 1:
                    raise PeerClientError("invalid peer response")
            if not response.endswith(b"\n") or response.count(b"\n") != 1:
                raise PeerClientError("invalid peer response")
            value = json.loads(
                response[:-1].decode("utf-8"),
                object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            expected_statuses = STATUSES[next(iter(request))]
            if (
                not isinstance(value, dict)
                or value.get("status") not in expected_statuses
            ):
                raise PeerClientError("invalid peer response")
            if value["status"] == "ok" and "search" in request:
                if (
                    set(value) != {"status", "actor", "items"}
                    or not isinstance(value["actor"], str)
                    or not value["actor"]
                    or not isinstance(value["items"], list)
                    or any(
                        not isinstance(item, dict)
                        or set(item) != {"kind", "urn"}
                        or item["kind"] not in {"doc", "folder"}
                        or not isinstance(item["urn"], str)
                        for item in value["items"]
                    )
                ):
                    raise PeerClientError("invalid peer response")
            elif set(value) != {"status"}:
                raise PeerClientError("invalid peer response")
            return value
    except PeerClientError:
        raise
    except (OSError, ValueError, TypeError, UnicodeDecodeError, struct.error) as exc:
        raise PeerClientError("peer outcome requires reconciliation") from exc
