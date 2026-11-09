import pytest

from phantomdocs.workflow_audit_evidence import prepare_evidence
from phantomdocs.workflows import WorkflowError


def test_evidence_does_not_claim_an_audit_or_equate_names_with_registration():
    tree = {
        "version": 1,
        "root_ref": "gdrive://root",
        "complete": True,
        "items": [
            {
                "id": "file-id",
                "name": "minutes.pdf",
                "mimeType": "application/pdf",
                "parents": ["root"],
            }
        ],
    }
    result = prepare_evidence(tree, b"An old entry named minutes.pdf")
    assert result["complete_audit"] is False
    assert result["items"][0]["name_in_matrix"] is True
    assert result["items"][0]["id_in_matrix"] is False


def test_incomplete_or_ambiguous_inventory_is_refused():
    item = {"id": "same", "name": "x", "mimeType": "text/plain", "parents": ["root"]}
    tree = {
        "version": 1,
        "root_ref": "gdrive://root",
        "complete": True,
        "items": [item, item],
    }
    with pytest.raises(WorkflowError):
        prepare_evidence(tree, b"matrix")
    tree.update(complete=False, items=[])
    with pytest.raises(WorkflowError):
        prepare_evidence(tree, b"matrix")
