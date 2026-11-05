"""Local peer archive indexing retains the native authorization boundary."""

import json
import sys

import pytest
from test_workflow_handover import Reader, prepared, store  # noqa: F401

from phantomdocs.manifest import load
from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_local_peer_archive import index_peer_archive
from phantomdocs.workflows import WorkflowError


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux private custody")
def test_custodied_peer_archive_indexes_once(prepared, store, tmp_path, monkeypatch):  # noqa: F811
    org, ledger_path = prepared[0][0], prepared[0][4]
    receipt = prepared[3]
    directory = tmp_path / "receipts"
    directory.mkdir(mode=0o700)
    path = directory / (receipt["request_id"] + ".json")
    path.write_text(json.dumps(receipt))
    path.chmod(0o600)
    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_archive.resolve_peer_actor",
        lambda *_: "coordinator",
    )
    reader = Reader(receipt)
    with WorkflowLedger(ledger_path) as ledger:
        options = {
            "identity_map": "/protected/map",
            "receipt_directory": str(directory),
            "ledger": ledger,
            "org": org,
            "root": store[0],
            "org_yaml": store[1],
            "drive_reader": reader,
        }
        first = index_peer_archive(object(), receipt["request_id"], **options)
        second = index_peer_archive(object(), receipt["request_id"], **options)
        assert first["state"] == second["state"] == "indexed"
        assert len(reader.downloads) == 2
        nodes = load(str(store[0] / "manifest.yaml"))["nodes"]
        assert len([node for node in nodes if node["kind"] == "doc"]) == 2


@pytest.mark.parametrize("request_id", ["", "../a", "/a", "a.json", "a/b"])
def test_invalid_request_id_rejected_before_identity_or_storage(
    request_id, monkeypatch
):
    def fail(*args, **kwargs):
        pytest.fail("invalid request reached identity or storage")

    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_archive.resolve_peer_actor", fail
    )
    with pytest.raises(WorkflowError, match="identifier"):
        index_peer_archive(
            object(),
            request_id,
            identity_map="/map",
            receipt_directory="/private",
            ledger=None,
            org={},
            root="/store",
            org_yaml="/org",
            drive_reader=None,
        )


def test_unmapped_peer_never_reads_receipt(monkeypatch):
    def reject(*_):
        raise WorkflowError("unmapped peer")

    def fail(*_):
        pytest.fail("unmapped peer reached receipt storage")

    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_archive.resolve_peer_actor", reject
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_archive.trusted_receipt_directory", fail
    )
    with pytest.raises(WorkflowError, match="unmapped peer"):
        index_peer_archive(
            object(),
            "request",
            identity_map="/map",
            receipt_directory="/private",
            ledger=None,
            org={},
            root="/store",
            org_yaml="/org",
            drive_reader=None,
        )
