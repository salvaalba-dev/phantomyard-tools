"""Bounded local broker for a matrix reader, with policy locks through delivery.

The host must pass root-controlled configuration and an authority context. One
broker is bound to one actor and one trusted viewer service UID. The viewer
must authenticate the HTTP session and restrict it to the bound actor before
requesting data. A client acknowledgement releases the policy locks only after
the viewer has completed its bounded response.
"""

import json
import socket
import struct
import time

from .view_matrix import MAX_MATRIX_BYTES, read_matrix
from .workflows import WorkflowError

TIMEOUT = 30
MAX_REQUEST = 256
ACK = b"delivered\n"


def _line(connection, limit):
    data = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while len(data) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request timed out")
        connection.settimeout(remaining)
        chunk = connection.recv(1)
        if not chunk:
            raise ValueError("incomplete request")
        data.extend(chunk)
        if chunk == b"\n":
            return bytes(data)
    raise ValueError("request too large")


def serve(connection, *, client_uid, actor, binding, authority):
    """Serve one already accepted Unix stream with trusted host dependencies."""
    connection.settimeout(TIMEOUT)
    try:
        if (
            connection.family != socket.AF_UNIX
            or connection.type & 0xF != socket.SOCK_STREAM
            or type(client_uid) is not int
            or client_uid < 0
            or not isinstance(actor, str)
            or not actor
        ):
            raise ValueError("invalid broker configuration")
        pid, uid, _ = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if pid <= 0 or uid != client_uid:
            raise ValueError("unexpected peer")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate request field")
                result[key] = value
            return result

        request = json.loads(_line(connection, MAX_REQUEST), object_pairs_hook=unique)
        if (
            not isinstance(request, dict)
            or set(request) != {"version"}
            or not isinstance(request["version"], str)
        ):
            raise ValueError("invalid request")
        with authority(actor) as (org, manifest, reader):
            text = read_matrix(
                **binding,
                version=request["version"],
                actor=actor,
                org=org,
                manifest=manifest,
                read_reference=reader,
            )
            response = json.dumps({"matrix": text}, ensure_ascii=True).encode() + b"\n"
            if len(response) > MAX_MATRIX_BYTES * 6 + 64:
                raise ValueError("response too large")
            connection.settimeout(TIMEOUT)
            connection.sendall(response)
            if _line(connection, len(ACK)) != ACK:
                raise ValueError("delivery not acknowledged")
    except (OSError, ValueError, TypeError, KeyError, struct.error, WorkflowError):
        try:
            connection.sendall(b'{"error":"matrix unavailable"}\n')
        except OSError:
            pass
    finally:
        connection.close()
