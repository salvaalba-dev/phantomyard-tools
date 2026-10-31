"""Translate an operator-reviewed legacy AU delivery record into review claims.

Parsing these fields does not authenticate the receipt, establish authorization,
or prove that registration or publication happened.
"""

import re

from phantomdocs.workflows import WorkflowError, reference_is_safe


def delivery_claims(receipt, *, inbox_item_ref, declared_inbox_ref):
    if (
        not isinstance(receipt, dict)
        or receipt.get("status")
        != "intake-delivery-verified-awaiting-native-registration"
    ):
        raise WorkflowError("unsupported delivery receipt")
    if (
        not isinstance(inbox_item_ref, str)
        or not inbox_item_ref.startswith("gdrive://")
        or not reference_is_safe(inbox_item_ref)
    ):
        raise WorkflowError("invalid intake reference")
    if (
        not isinstance(declared_inbox_ref, str)
        or not declared_inbox_ref.startswith("gdrive://")
        or not reference_is_safe(declared_inbox_ref)
    ):
        raise WorkflowError("invalid inbox reference")
    if receipt.get("inbox_id") != declared_inbox_ref.removeprefix("gdrive://"):
        raise WorkflowError("delivery receipt inbox mismatch")
    source = receipt.get("source_ref")
    if (
        not isinstance(source, str)
        or not source.startswith("gdrive://")
        or not reference_is_safe(source)
    ):
        raise WorkflowError("invalid archive reference")
    files = receipt.get("files")
    if (
        not isinstance(files, list)
        or not 1 <= len(files) <= 100
        or any(not isinstance(item, dict) for item in files)
    ):
        raise WorkflowError("invalid delivery receipt files")
    found = [
        item
        for item in files
        if item.get("id") == inbox_item_ref.removeprefix("gdrive://")
    ]
    if len(found) != 1 or found[0].get("verified") is not True:
        raise WorkflowError("unverified or ambiguous delivered item")
    digest = found[0].get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise WorkflowError("invalid delivered item digest")
    return {"inbox_ref": inbox_item_ref, "archive_ref": source, "sha256": digest}
