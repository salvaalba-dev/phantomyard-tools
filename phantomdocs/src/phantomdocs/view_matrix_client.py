"""Session-bound client for a separately supervised matrix broker."""

import json
import socket
import struct

from .view_matrix import MAX_MATRIX_BYTES
from .view_matrix_broker import ACK, MAX_REQUEST, TIMEOUT, _line
from .workflow_audit_authority import project_category
from .workflows import WorkflowError


def deliver(*, gate, headers, version, routes, send):
    """Deliver a broker response while the broker retains its policy locks.

    The host supplies reviewed routes, enforces a bounded HTTP response, and
    must not expose route, UID, actor or project settings to HTTP input.
    """
    recipient, directory = gate.identified_scope(headers)
    actor = getattr(recipient, "persona", None)
    if getattr(recipient, "human", None) is not None or actor not in routes:
        raise WorkflowError("matrix unavailable")
    route = routes[actor]
    if not isinstance(route, dict) or set(route) != {
        "socket",
        "server_uid",
        "domain",
        "project_type",
        "scope_id",
    }:
        raise WorkflowError("matrix unavailable")
    if (
        not isinstance(route["socket"], str)
        or not route["socket"].startswith("/")
        or type(route["server_uid"]) is not int
        or route["server_uid"] < 0
        or not isinstance(version, str)
    ):
        raise WorkflowError("matrix unavailable")

    def permitted(current, current_directory):
        org = current_directory.org
        project = route["scope_id"]
        resource = {
            "organization": org["organization"]["id"],
            "secret": False,
            "scope": {"id": project, "kind": "project"},
            "project": project,
            "category": project_category(org, route["domain"], route["project_type"]),
        }
        return current_directory.permits(current, resource)

    if not permitted(recipient, directory):
        raise WorkflowError("matrix unavailable")
    request = json.dumps({"version": version}).encode() + b"\n"
    if len(request) > MAX_REQUEST:
        raise WorkflowError("matrix unavailable")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(TIMEOUT)
            connection.connect(route["socket"])
            pid, uid, _ = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if pid <= 0 or uid != route["server_uid"]:
                raise ValueError("unexpected broker")
            connection.sendall(request)
            response = json.loads(_line(connection, MAX_MATRIX_BYTES * 6 + 64))
            if (
                not isinstance(response, dict)
                or set(response) != {"matrix"}
                or not isinstance(response["matrix"], str)
            ):
                raise ValueError("invalid response")
            current, current_directory = gate.identified_scope(headers)
            if current != recipient or not permitted(current, current_directory):
                raise ValueError("session changed")
            send(response["matrix"])
            try:
                connection.sendall(ACK)
            except OSError:
                # HTTP delivery has already happened; never emit a second response.
                pass
    except (OSError, ValueError, TypeError, KeyError, struct.error) as exc:
        raise WorkflowError("matrix unavailable") from exc
