"""Prepare bounded, read-only evidence for an agent's document review.

Literal matches are leads for review, not proof of registration or an audit
verdict. The caller owns authentication and obtains the matrix and inventory.
"""

import hashlib
import json
import time

from .workflow_drive_tree import FOLDER
from .workflows import WorkflowError

MAX_MATRIX_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 5000
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024


def prepare_evidence(tree, matrix_bytes):
    """Bind a complete point-in-time inventory to the exact matrix bytes."""
    if (
        not isinstance(matrix_bytes, bytes)
        or not 0 < len(matrix_bytes) <= MAX_MATRIX_BYTES
    ):
        raise WorkflowError("invalid matrix evidence size")
    try:
        matrix = matrix_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise WorkflowError("matrix evidence must be UTF-8") from exc
    if (
        not isinstance(tree, dict)
        or tree.get("version") != 1
        or tree.get("complete") is not True
        or not isinstance(tree.get("root_ref"), str)
        or not tree["root_ref"].startswith("gdrive://")
        or not isinstance(tree.get("items"), list)
        or len(tree["items"]) > MAX_ITEMS
    ):
        raise WorkflowError("complete bounded inventory required")
    seen = set()
    rows = []
    for item in tree["items"]:
        if not isinstance(item, dict):
            raise WorkflowError("invalid inventory item")
        identity, name, kind, parents = (
            item.get("id"),
            item.get("name"),
            item.get("mimeType"),
            item.get("parents"),
        )
        if (
            not isinstance(identity, str)
            or not identity
            or identity in seen
            or not isinstance(name, str)
            or not name
            or not isinstance(kind, str)
            or not kind
            or not isinstance(parents, list)
            or not parents
            or not all(isinstance(p, str) and p for p in parents)
            or item.get("trashed", False) is not False
        ):
            raise WorkflowError("invalid or duplicate inventory identity")
        seen.add(identity)
        rows.append(
            {
                "id": identity,
                "name": name,
                "mime_type": kind,
                "parents": parents,
                "version": item.get("version"),
                "is_folder": kind == FOLDER,
                "id_in_matrix": identity in matrix,
                "name_in_matrix": name in matrix,
            }
        )
    result = {
        "version": 1,
        "kind": "document-review-evidence",
        "complete_audit": False,
        "created_at": int(time.time()),
        "root_ref": tree["root_ref"],
        "matrix_sha256": hashlib.sha256(matrix_bytes).hexdigest(),
        "matrix_text": matrix,
        "items": rows,
    }
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise WorkflowError("review evidence exceeds output limit")
    return result
