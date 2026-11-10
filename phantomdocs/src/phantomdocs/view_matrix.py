"""Read explicitly pinned external matrix versions without creating records.

The hosting reader must authenticate the session, bind its actor independently
of request parameters, and hold its current policy and manifest locks until the
response is delivered. This module does not provide a network endpoint.
"""

import hashlib
import re

from .workflow_audit_authority import project_category
from .workflow_audit_native_acl import authorize_observations
from .workflows import WorkflowError

MAX_MATRIX_BYTES = 2 * 1024 * 1024
_REF = re.compile(r"gdrive://[A-Za-z0-9_-]{10,200}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")


def read_matrix(
    *,
    versions,
    version,
    actor,
    org,
    manifest,
    root_ref,
    domain,
    project_type,
    read_reference,
):
    """Verify and authorize a trusted configured version using the caller's reader.

    The trusted host supplies the actor, version configuration, Drive reader,
    current organization and manifest. The version selector is not a Drive
    reference, path, actor, category or credential. It creates no catalog entry.
    """
    if (
        not isinstance(versions, dict)
        or not versions
        or not isinstance(version, str)
        or version not in versions
        or not isinstance(actor, str)
        or not actor
        or not isinstance(root_ref, str)
        or not _REF.fullmatch(root_ref)
    ):
        raise WorkflowError("matrix unavailable")
    record = versions[version]
    if (
        not isinstance(record, dict)
        or set(record) != {"ref", "sha256"}
        or not isinstance(record["ref"], str)
        or not _REF.fullmatch(record["ref"])
        or not isinstance(record["sha256"], str)
        or not _HASH.fullmatch(record["sha256"])
    ):
        raise WorkflowError("matrix unavailable")
    try:
        category = project_category(org, domain, project_type)
        authorize_observations(
            {
                "root_ref": root_ref,
                "matrix_ref": record["ref"],
                "matrix_text": "",
                "items": [],
            },
            org,
            actor,
            manifest,
            root_ref=root_ref,
            matrix_ref=record["ref"],
            project_category=category,
        )
        data = read_reference(record["ref"], MAX_MATRIX_BYTES + 1)
        if (
            not isinstance(data, bytes)
            or len(data) > MAX_MATRIX_BYTES
            or hashlib.sha256(data).hexdigest() != record["sha256"]
        ):
            raise ValueError("unverified matrix bytes")
        text = data.decode("utf-8")
        authorize_observations(
            {
                "root_ref": root_ref,
                "matrix_ref": record["ref"],
                "matrix_text": text,
                "items": [],
            },
            org,
            actor,
            manifest,
            root_ref=root_ref,
            matrix_ref=record["ref"],
            project_category=category,
        )
    except (ValueError, OSError, UnicodeError, WorkflowError) as exc:
        raise WorkflowError("matrix unavailable") from exc
    return text
