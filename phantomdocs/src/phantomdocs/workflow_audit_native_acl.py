"""Check inherited project scope and known native document restrictions.

The caller must hold the PhantomOrg and native manifest locks throughout the
check and delivery. This helper does not establish folder-to-project authority.
"""

import re

from .access import can_read
from .manifest import structural_issues, validate
from .workflow_visibility import can_observe_node
from .workflows import WorkflowError


def authorize_observations(
    evidence, org, actor, manifest, *, root_ref, matrix_ref, project_category
):
    if (
        not isinstance(evidence, dict)
        or evidence.get("root_ref") != root_ref
        or evidence.get("matrix_ref") != matrix_ref
        or not isinstance(evidence.get("matrix_text"), str)
        or not isinstance(evidence.get("items"), list)
        or not isinstance(project_category, str)
        or not can_read(org, actor, project_category)
        or not isinstance(manifest, dict)
        or validate(manifest)
        or structural_issues(manifest)
    ):
        raise WorkflowError("review evidence unavailable")
    ids = set()
    for item in evidence["items"]:
        identity = item.get("id") if isinstance(item, dict) else None
        if (
            not isinstance(identity, str)
            or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,255}", identity) is None
            or identity in ids
        ):
            raise WorkflowError("review evidence unavailable")
        ids.add(identity)
    # The matrix is free text: it may describe a restricted document without
    # including its Drive identity or exact name. Until there is a trusted,
    # complete matrix-to-document classification, require access to every
    # native document version before releasing the unfiltered matrix.
    for node in manifest["nodes"]:
        if node.get("kind") == "doc" and not can_observe_node(
            org, actor, manifest, node
        ):
            raise WorkflowError("review evidence unavailable")
