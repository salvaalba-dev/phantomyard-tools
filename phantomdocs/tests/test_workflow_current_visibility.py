"""Historical versions cannot disclose a document whose current head is denied."""

from copy import deepcopy

import pytest
import test_workflow_scan as fixtures

from phantomdocs import workflow_peer_lookup, workflow_peer_search
from phantomdocs.manifest import validate
from phantomdocs.workflow_reconcile import review_copy
from phantomdocs.workflow_scan import scan
from phantomdocs.workflows import WorkflowError


@pytest.fixture
def restricted_head():
    system = fixtures.system.__wrapped__()
    old = fixtures.index(system)
    current = deepcopy(old)
    current.update(mac="4" * 64, previous=old["mac"], category="category-3")
    current["locations"] = [{"backend": "gdrive", "ref": "new-file"}]
    system[6]["nodes"].append(current)
    assert not validate(system[6])
    return system, old, current


def test_scan_holds_historical_reference_and_link(restricted_head):
    system, old, _ = restricted_head
    row = scan(*system)["items"][0]
    assert row["state"] == "held" and "urn" not in row and "job" not in row
    old["locations"] = [{"backend": "gdrive", "ref": "archived-file"}]
    row = scan(
        *system,
        local_links={
            "gdrive://example-file": {"node": old, "inbox_name": "coordinator"}
        },
    )["items"][0]
    assert row["state"] == "held" and "urn" not in row and "job" not in row


def test_reconciliation_does_not_disclose_historical_identity(restricted_head):
    system, _, _ = restricted_head
    result = review_copy(
        inbox_ref="gdrive://intake-copy",
        archive_ref="gdrive://example-file",
        receipt_inbox_ref="gdrive://intake-copy",
        receipt_archive_ref="gdrive://example-file",
        observed_sha256="3" * 64,
        receipt_sha256="3" * 64,
        org=system[2],
        caller="coordinator",
        manifest=system[6],
    )
    assert result["reason"] == "reference-unavailable-or-unauthorized"
    assert "urn" not in result


def test_readable_current_head_keeps_historical_reference_available(restricted_head):
    system, old, current = restricted_head
    current["category"] = old["category"]
    row = scan(*system)["items"][0]
    assert row["state"] == "indexed-reference"
    assert row["urn"] == old["urn"]


def test_ambiguous_history_is_refused_before_search_or_lookup(
    monkeypatch, restricted_head
):
    system, old, current = restricted_head
    fork = deepcopy(current)
    fork.update(
        mac="5" * 64, category="category-2", previous=old["mac"], contentHash="6" * 64
    )
    system[6]["nodes"].append(fork)
    assert not validate(system[6])
    monkeypatch.setattr(
        workflow_peer_search, "resolve_peer_actor", lambda *_: "coordinator"
    )
    monkeypatch.setattr(
        workflow_peer_lookup, "resolve_peer_actor", lambda *_: "coordinator"
    )
    common = {
        "identity_map": "/synthetic",
        "org": system[2],
        "load_manifest": lambda: deepcopy(system[6]),
    }
    with pytest.raises(ValueError, match="invalid manifest"):
        workflow_peer_search.search_peer(object(), {"query": "source"}, **common)
    with pytest.raises(ValueError, match="invalid manifest"):
        workflow_peer_lookup.lookup_peer(object(), {"operation": "refs"}, **common)
    with pytest.raises(WorkflowError, match="invalid native manifest"):
        scan(*system)


def test_protected_search_lookup_and_refs_check_current_head(
    monkeypatch, restricted_head
):
    system, old, _ = restricted_head
    system[6]["refs"] = {"historical": old["mac"]}
    monkeypatch.setattr(
        workflow_peer_search, "resolve_peer_actor", lambda *_: "coordinator"
    )
    monkeypatch.setattr(
        workflow_peer_lookup, "resolve_peer_actor", lambda *_: "coordinator"
    )
    common = {
        "identity_map": "/synthetic",
        "org": system[2],
        "load_manifest": lambda: deepcopy(system[6]),
    }
    assert (
        workflow_peer_search.search_peer(object(), {"query": "source"}, **common)[
            "items"
        ]
        == []
    )
    assert (
        workflow_peer_lookup.lookup_peer(object(), {"operation": "refs"}, **common)[
            "result"
        ]
        == []
    )
    status = workflow_peer_lookup.lookup_peer(
        object(), {"operation": "status"}, **common
    )["result"]
    assert status["docs"] == 0
    for operation in ("reference", "content-reference"):
        with pytest.raises(ValueError, match="document unavailable"):
            workflow_peer_lookup.lookup_peer(
                object(),
                {"operation": operation, "ref": old["urn"], "mac": old["mac"]},
                **common,
            )
