"""Consume a custodied archive receipt for an authenticated local peer.

The host must provide trusted configuration and synchronize policy changes.
This module does not create a listener, move files, or authenticate a human.
"""

import re

from .workflow_handover import index_archive
from .workflow_local_identity import resolve_peer_actor
from .workflow_receipt_store import read_receipt, trusted_receipt_directory
from .workflows import WorkflowError

_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")


def index_peer_archive(
    connection,
    request_id,
    *,
    identity_map,
    receipt_directory,
    ledger,
    org,
    root,
    org_yaml,
    drive_reader,
):
    """Use a kernel-bound actor and a service-owned receipt for native indexing.

    All keyword arguments must come from trusted service configuration. The
    request selects only a bounded receipt identifier; it cannot select a path,
    actor, category, owner, Drive credential, or destination. The native indexer
    rechecks the pinned processor, policy, archived bytes and destination.
    """
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise WorkflowError("invalid archive request identifier")
    actor = resolve_peer_actor(identity_map, connection)
    with trusted_receipt_directory(receipt_directory) as directory_fd:
        receipt = read_receipt(directory_fd, request_id + ".json")
    if receipt.get("request_id") != request_id:
        raise WorkflowError("archive receipt request identifier mismatch")
    return index_archive(
        ledger,
        receipt,
        org,
        actor,
        root=root,
        org_yaml=org_yaml,
        drive_reader=drive_reader,
    )
