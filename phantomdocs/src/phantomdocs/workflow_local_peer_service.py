"""Single-connection entry point for a supervised local admission service.

The supervisor must create and protect the Unix listener and its parent path.
The context factory must open a private ledger and planner for each request.
Every writer of the organization policy must use the same lock; this module
cannot enforce cooperation by privileged or older writers. This module does not
install or run a daemon or execute admitted jobs.
"""

import socket
from copy import deepcopy

from .access import policy_hash, validate_org_schema
from .workflow_local_peer_protocol import serve_connection
from .workflow_policy_guard import policy_guard


def serve_one(listener, context_factory, *, policy_lock, load_org):
    """Handle one peer using a fresh, trusted per-request context.

    The host must provide protected configuration and a trusted organization
    loader. The factory receives a fresh policy snapshot and returns a context
    manager yielding keyword arguments for ``serve_connection``. Hold the
    shared policy lock through request handling and context cleanup. An
    exception never results in admission and the peer is always closed.
    """
    if not isinstance(listener, socket.socket):
        raise ValueError("a real supervised Unix listener is required")  # noqa: TRY004
    if (
        listener.family != socket.AF_UNIX
        or listener.type & 0xF != socket.SOCK_STREAM
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
    ):
        raise ValueError("a listening Unix stream socket is required")
    connection, _ = listener.accept()
    try:
        with policy_guard(policy_lock, exclusive=False):
            org = deepcopy(load_org())
            if not isinstance(org, dict):
                raise ValueError("trusted organization must be an object")  # noqa: TRY004
            validate_org_schema(org)
            expected = policy_hash(org)
            with context_factory(org) as context:
                if not isinstance(context, dict) or "org" not in context:
                    raise ValueError("trusted context has no organization")
                if policy_hash(context["org"]) != expected:
                    raise ValueError("trusted context uses a different policy")
                serve_connection(connection, **context)
    finally:
        connection.close()
