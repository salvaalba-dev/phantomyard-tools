"""Bounded single-request local workflow admission and archive protocol.

The trusted host owns the listener, configuration, ledger lifecycle, and audit
logging. This module does not provide a daemon, move files, synchronize policy
changes, or execute accepted requests.
"""

import json

from .workflow_local_peer import accept_peer_job
from .workflow_local_peer_archive import index_peer_archive

MAX_REQUEST_BYTES = 64 * 1024


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate request field")
        result[key] = value
    return result


def _read_request(connection):
    data = bytearray()
    while b"\n" not in data:
        chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 2 - len(data)))
        if not chunk:
            raise ValueError("incomplete request")
        data.extend(chunk)
        if len(data) > MAX_REQUEST_BYTES + 1:
            raise ValueError("request exceeds limit")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise ValueError("invalid request framing")
    request = json.loads(
        data[:-1].decode("utf-8"),
        object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid constant")),
    )
    if not isinstance(request, dict) or set(request) not in ({"job"}, {"archive"}):
        raise ValueError("invalid request")
    return request


def serve_connection(
    connection, *, identity_map, ledger, org, make_plan, archive_context=None
):
    """Handle one request using exclusively host-provided trusted context."""
    connection.settimeout(5)
    try:
        request = _read_request(connection)
        if "job" in request:
            result = accept_peer_job(
                connection,
                identity_map,
                request["job"],
                ledger=ledger,
                org=org,
                make_plan=make_plan,
            )
            status = "blocked" if result.get("state") == "blocked" else "received"
        else:
            if archive_context is None:
                raise ValueError("archive indexing is unavailable")
            index_peer_archive(
                connection,
                request["archive"],
                identity_map=identity_map,
                ledger=ledger,
                org=org,
                **archive_context,
            )
            status = "indexed"
        response = {"status": status}
    except Exception:  # noqa: BLE001
        # A caller cannot distinguish authorization, parser, or storage failures.
        response = {"status": "rejected"}
    connection.sendall((json.dumps(response, separators=(",", ":")) + "\n").encode())
