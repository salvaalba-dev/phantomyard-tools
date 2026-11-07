"""Drive tree traversal is bounded, read-only and fails on ambiguous results."""

from copy import deepcopy

import pytest
from click.testing import CliRunner

from phantomdocs import workflow_drive_tree
from phantomdocs.cli import main
from phantomdocs.workflow_drive_tree import FOLDER, inventory_tree
from phantomdocs.workflows import WorkflowError


def item(identity, parent, mime="text/plain", **extra):
    return {
        "id": identity,
        "name": identity,
        "mimeType": mime,
        "parents": [parent],
        **extra,
    }


class Reader:
    def __init__(self, folders):
        self.folders = folders
        self.calls = []

    def inventory(self, ref):
        self.calls.append(ref)
        return deepcopy(self.folders[ref])


def listing(*items):
    return {"version": 1, "complete": True, "items": list(items)}


def test_walks_folders_but_does_not_follow_shortcuts_or_trashed_items():
    reader = Reader(
        {
            "gdrive://root": listing(
                item("folder", "root", FOLDER),
                item("shortcut", "root", "application/vnd.google-apps.shortcut"),
                item("trashed", "root", FOLDER, trashed=True),
            ),
            "gdrive://folder": listing(item("document", "folder")),
        }
    )
    result = inventory_tree(reader, "gdrive://root")
    assert [x["id"] for x in result["items"]] == ["folder", "shortcut", "document"]
    assert reader.calls == ["gdrive://root", "gdrive://folder"]
    assert result["complete"] is True


def test_rejects_duplicate_identity_and_cycles():
    reader = Reader(
        {
            "gdrive://root": listing(
                item("folder", "root", FOLDER), item("file", "root")
            ),
            "gdrive://folder": listing(item("file", "folder")),
        }
    )
    with pytest.raises(WorkflowError, match="duplicate or cyclic"):
        inventory_tree(reader, "gdrive://root")
    reader.folders["gdrive://folder"] = listing(item("root", "folder", FOLDER))
    with pytest.raises(WorkflowError, match="duplicate or cyclic"):
        inventory_tree(reader, "gdrive://root")


def test_rejects_incomplete_wrong_parent_and_limits():
    reader = Reader({"gdrive://root": listing(item("child", "root", FOLDER))})
    reader.folders["gdrive://child"] = {"version": 1, "complete": False, "items": []}
    with pytest.raises(WorkflowError):
        inventory_tree(reader, "gdrive://root")
    reader.folders["gdrive://child"] = listing(item("file", "other"))
    with pytest.raises(WorkflowError, match="unexpected parent"):
        inventory_tree(reader, "gdrive://root")
    with pytest.raises(WorkflowError, match="folder limit"):
        inventory_tree(reader, "gdrive://root", max_folders=1)
    reader.folders["gdrive://root"] = listing(item("a", "root"), item("b", "root"))
    with pytest.raises(WorkflowError, match="item limit"):
        inventory_tree(reader, "gdrive://root", max_items=1)


@pytest.mark.parametrize(
    "root", ["file://root", "gdrive://root?token=secret", "gdrive://"]
)
def test_rejects_invalid_roots(root):
    with pytest.raises(WorkflowError):
        inventory_tree(Reader({}), root)


def test_cli_uses_explicit_token_and_root(tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("synthetic", encoding="utf-8")
    reader = Reader({"gdrive://root": listing(item("file", "root"))})
    monkeypatch.setattr(workflow_drive_tree, "DriveInboxInventory", lambda path: reader)
    result = CliRunner().invoke(
        main,
        [
            "workflow",
            "tree-inventory",
            "--root-ref",
            "gdrive://root",
            "--drive-token-file",
            str(token),
        ],
    )
    assert result.exit_code == 0
    assert '"id": "file"' in result.output
    assert reader.calls == ["gdrive://root"]
