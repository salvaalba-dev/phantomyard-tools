import pytest

from phantomdocs.workflow_audit_native_acl import authorize_observations
from phantomdocs.workflows import WorkflowError


def run(evidence, manifest):
    return authorize_observations(
        evidence,
        {},
        "alma",
        manifest,
        root_ref="gdrive://root",
        matrix_ref="gdrive://matrix",
        project_category="project",
    )


def test_project_inheritance_and_historical_restrictions(monkeypatch):
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.validate", lambda data: []
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.structural_issues", lambda data: []
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.can_read",
        lambda org, actor, category: category == "project",
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.can_observe_node",
        lambda org, actor, manifest, node: node["category"] != "restricted",
    )
    evidence = {
        "root_ref": "gdrive://root",
        "matrix_ref": "gdrive://matrix",
        "matrix_text": "matrix",
        "items": [{"id": "new"}],
    }
    manifest = {"nodes": []}
    run(evidence, manifest)
    manifest["nodes"].append(
        {
            "kind": "doc",
            "category": "restricted",
            "locations": [{"backend": "gdrive", "ref": "new"}],
        }
    )
    with pytest.raises(WorkflowError):
        run(evidence, manifest)


def test_matrix_mention_of_restricted_reference_is_denied_even_outside_tree(
    monkeypatch,
):
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.validate", lambda data: []
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.structural_issues", lambda data: []
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.can_read",
        lambda org, actor, category: True,
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.can_observe_node", lambda *args: False
    )
    evidence = {
        "root_ref": "gdrive://root",
        "matrix_ref": "gdrive://matrix",
        "matrix_text": "old-reference",
        "items": [],
    }
    manifest = {
        "nodes": [
            {
                "kind": "doc",
                "locations": [{"backend": "gdrive", "ref": "old-reference"}],
            }
        ]
    }
    with pytest.raises(WorkflowError):
        run(evidence, manifest)


def test_free_text_cannot_prove_a_restricted_document_is_absent(monkeypatch):
    monkeypatch.setattr("phantomdocs.workflow_audit_native_acl.validate", lambda _: [])
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.structural_issues", lambda _: []
    )
    monkeypatch.setattr("phantomdocs.workflow_audit_native_acl.can_read", lambda *args: True)
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_native_acl.can_observe_node", lambda *args: False
    )
    evidence = {
        "root_ref": "gdrive://root",
        "matrix_ref": "gdrive://matrix",
        "matrix_text": "An indirect description without a document identifier",
        "items": [],
    }
    with pytest.raises(WorkflowError):
        run(evidence, {"nodes": [{"kind": "doc", "locations": []}]})
