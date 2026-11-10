import hashlib

import pytest

from phantomdocs import view_matrix
from phantomdocs.workflows import WorkflowError


def test_pinned_version_and_live_authority(monkeypatch):
    content = {"gdrive://abcdefghij": b"older", "gdrive://abcdefghik": b"newer"}
    versions = {
        name: {"ref": ref, "sha256": hashlib.sha256(content[ref]).hexdigest()}
        for name, ref in [("v1", "gdrive://abcdefghij"), ("v2", "gdrive://abcdefghik")]
    }
    allow = {"value": True}
    monkeypatch.setattr(view_matrix, "project_category", lambda *args: "project")

    def authorize(evidence, org, actor, manifest, **kwargs):
        assert actor == "agent"
        assert evidence["matrix_ref"] == kwargs["matrix_ref"]
        if not allow["value"]:
            raise WorkflowError("revoked")

    monkeypatch.setattr(view_matrix, "authorize_observations", authorize)
    args = {
        "versions": versions,
        "actor": "agent",
        "org": {},
        "manifest": {},
        "root_ref": "gdrive://rootfolder1",
        "domain": "domain",
        "project_type": "project",
        "read_reference": lambda ref, limit: content[ref][:limit],
    }
    assert view_matrix.read_matrix(version="v1", **args) == "older"
    assert view_matrix.read_matrix(version="v2", **args) == "newer"
    allow["value"] = False
    with pytest.raises(WorkflowError, match="matrix unavailable"):
        view_matrix.read_matrix(version="v2", **args)
    allow["value"] = True
    content["gdrive://abcdefghik"] = b"modified"
    with pytest.raises(WorkflowError, match="matrix unavailable"):
        view_matrix.read_matrix(version="v2", **args)
    with pytest.raises(WorkflowError, match="matrix unavailable"):
        view_matrix.read_matrix(version="gdrive://abcdefghij", **args)
