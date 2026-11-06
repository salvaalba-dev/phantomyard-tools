"""Bounded local workflow admission, search and archive protocol.

The trusted host owns the listener, configuration, ledger lifecycle, and audit
logging. This module does not provide a daemon, move files, synchronize policy
changes, or execute accepted requests.
"""

import json

from .workflow_local_peer import accept_peer_job
from .workflow_local_peer_archive import index_peer_archive
from .workflow_peer_lookup import lookup_peer
from .workflow_peer_search import search_peer

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
    if not isinstance(request, dict) or set(request) not in (
        {"job"},
        {"archive"},
        {"search"},
        {"lookup"},
    ):
        raise ValueError("invalid request")
    return request


def serve_connection(
    connection,
    *,
    identity_map,
    ledger,
    org,
    make_plan,
    archive_context=None,
    load_search_manifest=None,
    search_guard=None,
):
    """Handle one request using exclusively host-provided trusted context."""
    connection.settimeout(5)
    sending_search = False
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
        elif "archive" in request:
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
        else:
            if load_search_manifest is None or search_guard is None:
                raise ValueError("search is unavailable")
            with search_guard():
                handler = search_peer if "search" in request else lookup_peer
                response = handler(
                    connection,
                    request["search"] if "search" in request else request["lookup"],
                    identity_map=identity_map,
                    org=org,
                    load_manifest=load_search_manifest,
                )
                sending_search = True
                connection.sendall(
                    (json.dumps(response, separators=(",", ":")) + "\n").encode()
                )
            return
        if "search" not in request:
            response = {"status": status}
    except Exception:  # noqa: BLE001
        # A caller cannot distinguish authorization, parser, or storage failures.
        if sending_search:
            return
        response = {"status": "rejected"}
    connection.sendall((json.dumps(response, separators=(",", ":")) + "\n").encode())
