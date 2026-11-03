"""Review a legacy control request against an existing native document.

This is evidence for an operator, not authority to change the control file,
register a document, or grant access. The digest must be obtained independently
from the current archived bytes by a trusted caller.
"""

import hashlib
import re

from .access import can_read
from .manifest import node_by_urn, structural_issues, validate
from .storage import location_uri
from .workflow_reconcile import OBSERVATION_FIELDS
from .workflows import WorkflowError, reference_is_safe

MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024


def _observed_archive_size(metadata):
    """Return a bounded binary size, or ``None`` for untrusted metadata."""
    size = metadata.get("size")
    # Bound the digit count before calling int().  Besides enforcing the
    # one-GiB review limit, this avoids parsing arbitrarily long provider
    # strings if a reader is faulty or malicious.
    if (
        not isinstance(size, str)
        or not size.isascii()
        or not size.isdigit()
        or len(size) > len(str(MAX_ARCHIVE_BYTES))
    ):
        return None
    value = int(size)
    return value if 0 < value <= MAX_ARCHIVE_BYTES else None


def review_control(control, *, observed_sha256, org, actor, manifest):
    """Return review-only evidence, withholding document identity when denied."""
    if (
        not isinstance(control, dict)
        or control.get("kind") != "operator-intake-request"
    ):
        raise WorkflowError("unsupported control request")
    ref = control.get("source_ref")
    digest = control.get("sha256")
    owners = control.get("owners")
    if (
        not isinstance(ref, str)
        or not ref.startswith("gdrive://")
        or not reference_is_safe(ref)
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not isinstance(observed_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", observed_sha256)
        or not isinstance(owners, list)
        or not owners
        or any(not isinstance(owner, str) or not owner for owner in owners)
        or len(owners) != len(set(owners))
        or not isinstance(control.get("category"), str)
    ):
        raise WorkflowError("invalid control evidence")
    if (
        validate(manifest)
        or structural_issues(manifest)
        or manifest["manifest"]["org"] != org.get("organization", {}).get("id")
        or control.get("organization") != manifest["manifest"]["org"]
    ):
        raise WorkflowError("invalid or mismatched organization")
    result = {"status": "review-required", "execution_ready": False}
    if observed_sha256 != digest:
        return {**result, "reason": "current-content-differs-from-request"}
    matches = []
    for node in manifest["nodes"]:
        if node.get("kind") != "doc":
            continue
        try:
            found = any(
                location_uri(loc) == ref for loc in (node.get("locations") or [])
            )
        except (TypeError, AttributeError, ValueError) as error:
            raise WorkflowError("invalid native reference location") from error
        if found and node_by_urn(manifest, node["urn"]) is node:
            matches.append(node)
    if not matches or any(
        not can_read(org, actor, node["category"]) for node in matches
    ):
        return {**result, "reason": "reference-unavailable-or-unauthorized"}
    if len(matches) != 1:
        return {**result, "reason": "ambiguous-archive-reference"}
    node = matches[0]
    if node.get("contentHash") != digest:
        return {**result, "reason": "archive-content-conflict"}
    if node.get("category") != control.get("category") or sorted(
        node.get("owners") or []
    ) != sorted(owners):
        return {**result, "reason": "classification-conflict"}
    return {**result, "reason": "matching-evidence", "urn": node["urn"]}


def review_control_from_archive(control, *, org, actor, manifest, reader):
    """Verify the current archived bytes after a read-only authorization check.

    The reader and organization must be supplied by the trusted host. A stable
    metadata observation is not an atomic lock and never authorizes changes.
    """
    if not isinstance(control, dict):
        raise WorkflowError("unsupported control request")
    result = review_control(
        control,
        observed_sha256=control.get("sha256"),
        org=org,
        actor=actor,
        manifest=manifest,
    )
    if result["reason"] != "matching-evidence":
        return result
    ref = control["source_ref"]
    reader.cache.pop(ref, None)
    before = reader.metadata(ref)
    size = _observed_archive_size(before)
    version = before.get("version")
    if (
        before.get("id") != ref.removeprefix("gdrive://")
        or before.get("trashed") is not False
        or size is None
        or not isinstance(version, str)
        or not version.isascii()
        or not version.isdigit()
    ):
        return {
            "status": "review-required",
            "execution_ready": False,
            "reason": "archive-metadata-unverified",
        }
    snapshot, location = reader.read_reference(ref, streaming=True)
    try:
        if location_uri(location) != ref:
            raise WorkflowError("reader returned a different reference")
        digest = hashlib.sha256()
        count = 0
        while chunk := snapshot.file.read(1024 * 1024):
            count += len(chunk)
            if count > size:
                raise WorkflowError("archive exceeds observed size")
            digest.update(chunk)
        if count != size:
            raise WorkflowError("archive size differs from observation")
    finally:
        snapshot.close()
    reader.cache.pop(ref, None)
    after = reader.metadata(ref)
    if any(before.get(field) != after.get(field) for field in OBSERVATION_FIELDS):
        return {
            "status": "review-required",
            "execution_ready": False,
            "reason": "archive-metadata-changed",
        }
    return review_control(
        control,
        observed_sha256=digest.hexdigest(),
        org=org,
        actor=actor,
        manifest=manifest,
    )
