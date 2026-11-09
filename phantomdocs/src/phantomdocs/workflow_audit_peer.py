"""Serve one bounded review request from a kernel-identified local agent.

The caller owns and protects the listener and must supervise this function.
This module neither installs a service nor collects or changes Drive files.
"""

import argparse
import json
import os
import socket
import struct

from .workflow_admission_config import _json
from .workflow_audit_authority import guarded_peer_authorizer
from .workflow_audit_evidence import MAX_EVIDENCE_BYTES
from .workflow_audit_mcp import read_evidence

TIMEOUT_SECONDS = 5
REQUEST = b'{"review":true}\n'


def serve_connection(connection, config_path):
    """Send the configured snapshot to the local client under both locks.

    The client and MCP broker may buffer it after the locks are released. A
    revocation cannot retract bytes already sent to the local client.
    """
    connection.settimeout(TIMEOUT_SECONDS)
    try:
        config = _json(config_path)
        if (
            not isinstance(config, dict)
            or set(config)
            != {"version", "authority_config", "evidence_path", "owner_uid"}
            or type(config["version"]) is not int
            or config["version"] != 1
            or type(config["owner_uid"]) is not int
            or config["owner_uid"] <= 0
            or not all(
                isinstance(config[k], str) and config[k].startswith("/")
                for k in ("authority_config", "evidence_path")
            )
        ):
            raise ValueError("invalid review service configuration")
        if (
            connection.family != socket.AF_UNIX
            or connection.type & 0xF != socket.SOCK_STREAM
        ):
            raise ValueError("Unix stream required")
        pid, uid, _ = struct.unpack(
            "3i",
            connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            ),
        )
        if pid <= 0 or uid != config["owner_uid"]:
            raise ValueError("unexpected peer")
        request = bytearray()
        while len(request) < len(REQUEST):
            chunk = connection.recv(len(REQUEST) - len(request))
            if not chunk:
                raise ValueError("incomplete request")
            request.extend(chunk)
        if bytes(request) != REQUEST:
            raise ValueError("unsupported request")
        with guarded_peer_authorizer(
            config["authority_config"], connection
        ) as authorize:
            evidence = read_evidence(config["evidence_path"], owner_uid=uid)
            authorize(evidence)
            result = (
                json.dumps({"evidence": evidence}, ensure_ascii=False).encode() + b"\n"
            )
            if len(result) > MAX_EVIDENCE_BYTES + 1024:
                raise ValueError("response too large")
            connection.sendall(result)
    except (OSError, ValueError, TypeError, KeyError, struct.error):
        try:
            connection.sendall(b'{"error":"review unavailable"}\n')
        except OSError:
            pass
    finally:
        connection.close()


def request_evidence(socket_path, *, expected_server_uid):
    """Connect only to a kernel-identified server and read its bounded reply."""
    if type(expected_server_uid) is not int or expected_server_uid < 0:
        raise ValueError("invalid server identity")
    if not isinstance(socket_path, str) or not socket_path.startswith("/"):
        raise ValueError("absolute socket path required")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(TIMEOUT_SECONDS)
        connection.connect(socket_path)
        pid, uid, _ = struct.unpack(
            "3i",
            connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            ),
        )
        if pid <= 0 or uid != expected_server_uid:
            raise ValueError("unexpected review server")
        connection.sendall(REQUEST)
        result = bytearray()
        while not result.endswith(b"\n"):
            chunk = connection.recv(min(65536, MAX_EVIDENCE_BYTES + 1025 - len(result)))
            if not chunk:
                raise ValueError("incomplete review response")
            result.extend(chunk)
            if len(result) > MAX_EVIDENCE_BYTES + 1024:
                raise ValueError("review response too large")
        value = json.loads(result)
        if (
            not isinstance(value, dict)
            or set(value) != {"evidence"}
            or not isinstance(value["evidence"], dict)
        ):
            raise ValueError("invalid review response")
        return value["evidence"]


def main():
    """Serve the single connection supplied as stdin by a socket supervisor."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    if os.name != "posix":
        raise SystemExit("Unix socket activation is required")
    try:
        connection = socket.socket(fileno=os.dup(0))
        if (
            connection.family != socket.AF_UNIX
            or connection.type & 0xF != socket.SOCK_STREAM
        ):
            raise ValueError("a connected Unix stream is required")
        connection.getpeername()
    except (OSError, ValueError):
        raise SystemExit("A supervised connection is required") from None
    serve_connection(connection, args.config)


if __name__ == "__main__":
    main()
