import hashlib
import io

import pytest

from phantomdocs.workflow_audit_snapshot import collect_evidence
from phantomdocs.workflows import WorkflowError


class Inventory:
    def __init__(self, items):
        self.items = items

    def inventory(self, ref):
        return {"version": 1, "complete": True, "items": self.items}


class Content:
    def __init__(self):
        self.file = io.BytesIO(b"matrix content")

    def close(self):
        self.file.close()


class Reader:
    def __init__(self, changed=False):
        self.calls = 0
        self.changed = changed

    def refresh_metadata(self, ref):
        self.calls += 1
        return {
            "id": "matrix",
            "size": "14",
            "version": str(self.calls if self.changed else 1),
            "parents": ["root"],
            "md5Checksum": hashlib.md5(b"matrix content").hexdigest(),
        }

    def read_reference(self, ref):
        return Content(), {}


def item(name, identity="matrix"):
    return {
        "id": identity,
        "name": name,
        "parents": ["root"],
        "mimeType": "text/markdown",
        "size": "14",
        "version": "1",
        "md5Checksum": hashlib.md5(b"matrix content").hexdigest(),
    }


def collect(items, reader):
    return collect_evidence(
        Inventory(items),
        reader,
        root_ref="gdrive://root",
        matrix_ref="gdrive://matrix",
        matrix_prefix="Matriz",
    )


def test_selected_latest_matrix_is_bound_to_verified_bytes():
    result = collect([item("Matriz_v22_20261005.md")], Reader())
    assert result["matrix_name"] == "Matriz_v22_20261005.md"
    assert result["complete_audit"] is False


@pytest.mark.parametrize(
    "items,reader",
    [
        (
            [item("Matriz_v22_20261005.md"), item("Matriz_v23_20261109.md", "other")],
            Reader(),
        ),
        ([item("Matriz_v22_20261005.md")], Reader(changed=True)),
    ],
)
def test_newer_or_changed_matrix_is_refused(items, reader):
    with pytest.raises(WorkflowError):
        collect(items, reader)
