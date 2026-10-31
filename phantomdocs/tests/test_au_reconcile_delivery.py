"""Legacy delivery records are only operator-reviewed claims."""

import importlib.util
from pathlib import Path

import pytest
import test_workflow_reconcile as reconcile_fixtures

from phantomdocs.workflow_reconcile import review_receipt
from phantomdocs.workflows import WorkflowError

spec = importlib.util.spec_from_file_location(
    "au_reconcile_delivery",
    Path(__file__).parents[1] / "contrib/au/reconcile_delivery.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def receipt():
    return {
        "status": "intake-delivery-verified-awaiting-native-registration",
        "inbox_id": "example-inbox",
        "source_ref": "gdrive://example-archive",
        "files": [
            {"id": "example-copy", "sha256": "a" * 64, "verified": True},
            {"id": "example-sidecar", "sha256": "b" * 64, "verified": True},
        ],
    }


def claims(receipt):
    return module.delivery_claims(
        receipt,
        inbox_item_ref="gdrive://example-copy",
        declared_inbox_ref="gdrive://example-inbox",
    )


def test_extracts_selected_item_not_sidecar(receipt):
    assert claims(receipt) == {
        "inbox_ref": "gdrive://example-copy",
        "archive_ref": "gdrive://example-archive",
        "sha256": "a" * 64,
    }


@pytest.mark.parametrize(
    "change", ["unverified", "duplicate", "other-inbox", "bad-digest", "other-status"]
)
def test_refuses_unreliable_claims(receipt, change):
    if change == "unverified":
        receipt["files"][0]["verified"] = False
    elif change == "duplicate":
        receipt["files"].append(dict(receipt["files"][0]))
    elif change == "other-inbox":
        receipt["inbox_id"] = "other-inbox"
    elif change == "bad-digest":
        receipt["files"][0]["sha256"] = "invalid"
    else:
        receipt["status"] = "unknown"
    with pytest.raises(WorkflowError):
        claims(receipt)


def test_selected_delivery_claims_feed_review_without_writing():
    import hashlib
    from copy import deepcopy

    system = reconcile_fixtures.system.__wrapped__()
    node = reconcile_fixtures.index(system)
    content = b"same bytes"
    digest = hashlib.sha256(content).hexdigest()
    node["contentHash"] = digest
    original = deepcopy(system[6])
    receipt = {
        "status": "intake-delivery-verified-awaiting-native-registration",
        "inbox_id": "shared-intake",
        "source_ref": "gdrive://example-file",
        "files": [{"id": "intake-copy", "sha256": digest, "verified": True}],
    }
    normalized = module.delivery_claims(
        receipt,
        inbox_item_ref="gdrive://intake-copy",
        declared_inbox_ref="gdrive://shared-intake",
    )
    result = review_receipt(
        receipt=normalized,
        inbox_ref="gdrive://intake-copy",
        inbox_name="coordinator",
        org=system[2],
        caller="coordinator",
        manifest=system[6],
        reader=reconcile_fixtures.FakeReader(content),
    )
    assert result["reason"] == "matching-evidence"
    assert result["execution_ready"] is False
    assert system[6] == original
