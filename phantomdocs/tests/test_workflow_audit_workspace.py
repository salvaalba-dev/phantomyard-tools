from pathlib import Path

import pytest

from phantomdocs.workflow_audit_workspace import DRIVE_READONLY, _collect
from phantomdocs.workflow_drive_inventory import DriveInboxInventory
from phantomdocs.workflow_drive_reader import DriveArchiveReader
from phantomdocs.workflows import WorkflowError


@pytest.mark.parametrize("token", ["", "bad token", "a\nb", None, "x" * 16385])
def test_in_memory_tokens_are_validated(token):
    with pytest.raises(WorkflowError):
        DriveInboxInventory.from_token(token)
    with pytest.raises(WorkflowError):
        DriveArchiveReader.from_token(token, max_bytes=100)


def test_token_is_read_only_and_removed_after_collection(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace.py"
    workspace.write_text(
        "def _get_creds(scopes):\n"
        f"    assert scopes == [{DRIVE_READONLY!r}]\n"
        "    return type('Creds', (), {'token': 'test-token'})()\n"
    )
    module = "phantomdocs.workflow_audit_workspace."
    monkeypatch.setattr(module + "validate_snapshot_directory", lambda path: Path(path))

    def reader(token, **kwargs):
        assert token == "test-token"
        return object()

    monkeypatch.setattr(module + "DriveInboxInventory.from_token", reader)
    monkeypatch.setattr(module + "DriveArchiveReader.from_token", reader)
    monkeypatch.setattr(
        module + "collect_evidence", lambda *args, **kwargs: {"ok": True}
    )
    monkeypatch.setattr(module + "publish_evidence", lambda output, evidence: evidence)
    assert _collect(workspace, "root", "matrix", "prefix", tmp_path) == {"ok": True}
    assert not list(tmp_path.glob(".review-token-*"))


def test_token_is_removed_when_inventory_fails(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace.py"
    workspace.write_text(
        "def _get_creds(scopes):\n    return type('C', (), {'token': 'secret'})()\n"
    )
    module = "phantomdocs.workflow_audit_workspace."
    monkeypatch.setattr(module + "validate_snapshot_directory", lambda path: Path(path))
    monkeypatch.setattr(
        module + "DriveInboxInventory.from_token",
        lambda token: (_ for _ in ()).throw(ValueError()),
    )
    with pytest.raises(ValueError):
        _collect(workspace, "root", "matrix", "prefix", tmp_path)
    assert not list(tmp_path.glob(".review-token-*"))
