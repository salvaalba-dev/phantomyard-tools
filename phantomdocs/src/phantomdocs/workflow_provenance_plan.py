"""Prepare, but never apply, a proposed audit link for an intake copy."""

from .access import can_write, policy_hash
from .manifest import node_by_urn, validate
from .storage import location_uri
from .workflows import WorkflowError, digest, reference_is_safe


def prepare_link(*, org, manifest, actor, urn, inbox_ref, archive_ref, sha256):
    """Pin current policy, document and references for a separate review.

    All evidence is caller-supplied. This function neither verifies bytes nor
    permits writing the audit log; application must independently revalidate.
    """
    if validate(manifest) or manifest["manifest"]["org"] != org.get(
        "organization", {}
    ).get("id"):
        raise WorkflowError("invalid or mismatched manifest")
    if any(
        not isinstance(ref, str)
        or not ref.startswith("gdrive://")
        or not reference_is_safe(ref)
        for ref in (inbox_ref, archive_ref)
    ):
        raise WorkflowError("invalid provider reference")
    node = node_by_urn(manifest, urn)
    if (
        not node
        or node.get("kind") != "doc"
        or not can_write(org, actor, node["category"], node.get("owners") or [])
    ):
        raise WorkflowError("document unavailable or actor not authorized")
    if node.get("contentHash") != sha256 or not any(
        location_uri(loc) == archive_ref for loc in (node.get("locations") or [])
    ):
        raise WorkflowError("document content or archived reference mismatch")
    return {
        "schema": "phantomdocs.intake-link-plan/v1",
        "status": "review-required",
        "execution_available": False,
        "actor": actor,
        "urn": urn,
        "document_mac": node["mac"],
        "content_sha256": sha256,
        "inbox_ref": inbox_ref,
        "archive_ref": archive_ref,
        "manifest_digest": digest(manifest),
        "policy_hash": policy_hash(org),
    }
