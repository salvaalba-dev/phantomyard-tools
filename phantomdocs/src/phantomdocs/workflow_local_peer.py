"""Admit a local workflow using a kernel-authenticated peer identity.

The service hosting this function must protect its listening socket, ledger,
organization policy and planner. This module does not create a socket, serve
requests, prove remote-human identity, or execute or archive a workflow.
"""

from .workflow_local_identity import resolve_peer_actor


def accept_peer_job(connection, identity_map, job, *, ledger, org, make_plan):
    """Authenticate the peer and delegate authorization to the native ledger.

    The protected map, ledger, policy and planner must come from trusted service
    configuration, never from the request. ``accept_local`` binds the resulting
    actor to the job requester and enforces the authorized plan.
    """
    actor = resolve_peer_actor(identity_map, connection)
    return ledger.accept_local(job, org, actor, make_plan)
