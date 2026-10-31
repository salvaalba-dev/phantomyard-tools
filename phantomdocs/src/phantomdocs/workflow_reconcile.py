"""Review one intake copy against independently supplied archival evidence.

This helper reads no provider content and does not authenticate its inputs. Its
result is evidence for review, never authority to publish, index or delete.
"""

import hashlib
import re

from .access import can_read
from .manifest import validate
from .storage import location_uri
from .workflows import WorkflowError, reference_is_safe

OBSERVATION_FIELDS = (
    "id",
    "parents",
    "size",
    "version",
    "trashed",
    "md5Checksum",
    "mimeType",
)


def metadata_unchanged(reader, inbox_ref, expected):
    """Refresh provider metadata; the result is not an atomic Drive lock."""
    reader.cache.pop(inbox_ref, None)
    current = reader.metadata(inbox_ref)
    return all(
        current.get(field) == expected.get(field) for field in OBSERVATION_FIELDS
    )


def review_copy(
    *,
    inbox_ref,
    archive_ref,
    receipt_inbox_ref,
    receipt_archive_ref,
    observed_sha256,
    receipt_sha256,
    org,
    caller,
    manifest,
):
    """Compare explicit references and digests without inferring identity by name."""
    for ref in (inbox_ref, archive_ref, receipt_inbox_ref, receipt_archive_ref):
        if not isinstance(ref, str) or not reference_is_safe(ref):
            raise WorkflowError("invalid reconciliation reference")
    for value in (observed_sha256, receipt_sha256):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise WorkflowError("invalid reconciliation digest")
    if validate(manifest) or manifest["manifest"]["org"] != org.get(
        "organization", {}
    ).get("id"):
        raise WorkflowError("invalid or mismatched native manifest")
    result = {"status": "review-required", "execution_ready": False}
    if (inbox_ref, archive_ref) != (receipt_inbox_ref, receipt_archive_ref):
        return {**result, "reason": "receipt-reference-conflict"}
    if observed_sha256 != receipt_sha256:
        return {**result, "reason": "current-content-differs-from-receipt"}
    matches = []
    for node in manifest["nodes"]:
        if node.get("kind") != "doc":
            continue
        try:
            found = any(
                location_uri(loc) == archive_ref
                for loc in (node.get("locations") or [])
            )
        except (TypeError, AttributeError, ValueError) as error:
            raise WorkflowError("invalid native reference location") from error
        if found:
            matches.append(node)
    # A generic result avoids revealing whether an inaccessible document exists.
    if not matches or any(
        not can_read(org, caller, node["category"]) for node in matches
    ):
        return {**result, "reason": "reference-unavailable-or-unauthorized"}
    if len({node["urn"] for node in matches}) != 1:
        return {**result, "reason": "ambiguous-archive-reference"}
    if any(node.get("contentHash") != receipt_sha256 for node in matches):
        return {**result, "reason": "archive-content-conflict"}
    return {**result, "reason": "matching-evidence", "urn": matches[0]["urn"]}


def review_receipt(*, receipt, inbox_ref, inbox_name, org, caller, manifest, reader):
    """Review trusted receipt claims against a bounded provider snapshot.

    The caller supplies a trusted receipt; its provenance is not authenticated
    here. Provider metadata is checked before and after reading.
    No result permits changes or asserts a remote sender's identity.
    """
    if not isinstance(receipt, dict) or set(receipt) != {
        "inbox_ref",
        "archive_ref",
        "sha256",
    }:
        raise WorkflowError("invalid copy reconciliation receipt")
    inbox = org.get("documents", {}).get("inboxes", {}).get(inbox_name)
    if not isinstance(inbox, dict) or not isinstance(inbox.get("id"), str):
        raise WorkflowError("inbox is not declared in PhantomOrg")
    inbox_folder = "gdrive://" + inbox["id"]
    if not reference_is_safe(inbox_folder):
        raise WorkflowError("invalid declared inbox folder reference")
    args = {
        "inbox_ref": inbox_ref,
        "archive_ref": receipt["archive_ref"],
        "receipt_inbox_ref": receipt["inbox_ref"],
        "receipt_archive_ref": receipt["archive_ref"],
        "receipt_sha256": receipt["sha256"],
        "org": org,
        "caller": caller,
        "manifest": manifest,
    }
    preliminary = review_copy(observed_sha256=receipt["sha256"], **args)
    if preliminary["reason"] != "matching-evidence":
        return preliminary
    reader.cache.pop(inbox_ref, None)
    before = reader.metadata(inbox_ref)
    if (
        before.get("id") != inbox_ref.removeprefix("gdrive://")
        or before.get("trashed") is not False
        or not isinstance(before.get("parents"), list)
        or not isinstance(before.get("version"), str)
        or not before["version"].isdigit()
        or inbox_folder.removeprefix("gdrive://") not in before.get("parents", [])
    ):
        return {
            "status": "review-required",
            "execution_ready": False,
            "reason": "inbox-membership-unverified",
        }
    snapshot, location = reader.read_reference(inbox_ref, streaming=True)
    try:
        if location_uri(location) != inbox_ref:
            raise WorkflowError("reader returned a different reference")
        sha = hashlib.sha256()
        while chunk := snapshot.file.read(1024 * 1024):
            sha.update(chunk)
    finally:
        snapshot.close()
    # DriveArchiveReader caches metadata; force an independent final observation.
    reader.cache.pop(inbox_ref, None)
    after = reader.metadata(inbox_ref)
    if any(before.get(field) != after.get(field) for field in OBSERVATION_FIELDS):
        return {
            "status": "review-required",
            "execution_ready": False,
            "reason": "inbox-metadata-changed",
        }
    result = review_copy(observed_sha256=sha.hexdigest(), **args)
    if result["reason"] == "matching-evidence":
        result["observed_metadata"] = {
            field: after.get(field) for field in OBSERVATION_FIELDS
        }
    return result
