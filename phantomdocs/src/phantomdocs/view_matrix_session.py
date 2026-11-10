"""Bind a protected matrix response to an identified PhantomView session.

The host owns the session gate, reviewed matrix bindings and authority context.
It must protect those inputs and bound I/O while holding the authority locks.
"""

from .view_matrix import read_matrix
from .workflow_audit_authority import project_category
from .workflows import WorkflowError


def deliver_matrix(*, gate, headers, version, bindings, authority, send):
    """Deliver only while the same identified session and policy remain valid.

    ``authority`` is a trusted context manager factory returning the current
    organization, native manifest and caller-specific Drive reader with their
    locks held. ``send`` must be bounded and execute before the context exits.
    Neither a document reference nor an actor can be chosen by the request.
    """
    recipient, directory = gate.identified_scope(headers)
    actor = getattr(recipient, "persona", None)
    if (
        getattr(recipient, "human", None) is not None
        or not isinstance(actor, str)
        or actor not in bindings
    ):
        raise WorkflowError("matrix unavailable")
    binding = bindings[actor]
    if not isinstance(binding, dict) or set(binding) != {
        "versions",
        "root_ref",
        "domain",
        "project_type",
        "scope_id",
    }:
        raise WorkflowError("matrix unavailable")
    with authority(actor) as (org, manifest, drive_reader):
        scope_id = binding["scope_id"]
        resource = {
            "organization": org["organization"]["id"],
            "secret": False,  # nosec B105 - classification flag, not a password
            "scope": {"id": scope_id, "kind": "project"},
            "project": scope_id,
            "category": project_category(
                org, binding["domain"], binding["project_type"]
            ),
        }
        if not directory.permits(recipient, resource):
            raise WorkflowError("matrix unavailable")
        result = read_matrix(
            **{key: value for key, value in binding.items() if key != "scope_id"},
            version=version,
            actor=actor,
            org=org,
            manifest=manifest,
            read_reference=drive_reader,
        )
        current, current_directory = gate.identified_scope(headers)
        if current != recipient or not current_directory.permits(current, resource):
            raise WorkflowError("matrix unavailable")
        send(result)
