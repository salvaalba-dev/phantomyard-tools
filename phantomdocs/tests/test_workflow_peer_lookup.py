"""Synthetic peer lookups never return unauthorized reference metadata."""

import json
from contextlib import nullcontext
from copy import deepcopy

import pytest
import test_workflow_scan as fixtures
from test_workflow_local_peer_protocol import Connection

from phantomdocs import workflow_peer_lookup as lookup
from phantomdocs.workflow_local_peer_protocol import serve_connection


@pytest.fixture
def system():
    data = fixtures.system.__wrapped__()
    fixtures.index(data, category="category-2")
    return data


def call(monkeypatch, system, payload, actor="coordinator"):
    monkeypatch.setattr(lookup, "resolve_peer_actor", lambda *_: actor)
    return lookup.lookup_peer(
        object(),
        payload,
        identity_map="/protected/map",
        org=system[2],
        load_manifest=lambda: deepcopy(system[6]),
    )


def test_authorized_reference_and_history(monkeypatch, system):
    ref = "urn:example-org:doc:project-reports/source"
    result = call(monkeypatch, system, {"operation": "reference", "ref": ref})
    assert result["result"] == {"urn": ref, "location": "gdrive://example-file"}
    result = call(monkeypatch, system, {"operation": "versions", "ref": ref})
    assert result["result"] == [{"mac": "2" * 64, "size": 0, "current": True}]


def test_content_reference_pins_exact_version_and_hash(monkeypatch, system):
    result = call(
        monkeypatch, system, {"operation": "content-reference", "ref": "source"}
    )
    assert result["result"] == {
        "urn": "urn:example-org:doc:project-reports/source",
        "location": "gdrive://example-file",
        "contentHash": "3" * 64,
        "mac": "2" * 64,
    }


def test_status_and_refs_include_only_authorized_nodes(monkeypatch, system):
    restricted = deepcopy(system[6]["nodes"][1])
    restricted.update(
        {
            "category": "category-3",
            "mac": "4" * 64,
            "urn": "urn:example-org:doc:project-reports/secret",
            "slug": "secret",
        }
    )
    system[6]["nodes"].append(restricted)
    system[6]["refs"] = {"visible": "2" * 64, "hidden": "4" * 64}
    result = call(monkeypatch, system, {"operation": "status"})["result"]
    assert result["nodes"] == 2 and result["docs"] == 1 and result["folders"] == 1
    rows = call(monkeypatch, system, {"operation": "refs"})["result"]
    assert rows == [
        {
            "name": "visible",
            "mac": "2" * 64,
            "urn": "urn:example-org:doc:project-reports/source",
        }
    ]


@pytest.mark.parametrize("operation", ["status", "refs"])
def test_status_and_refs_reject_claimed_actor(monkeypatch, system, operation):
    with pytest.raises(ValueError):
        call(monkeypatch, system, {"operation": operation, "actor": "other"})


@pytest.mark.parametrize(
    "location",
    [
        {"backend": "file", "ref": "/restricted/file"},
        {"backend": "gdrive", "ref": "--dangerous"},
        {"backend": "gdrive", "ref": "file;bad"},
    ],
)
def test_content_reference_rejects_non_drive_and_unsafe_ids(
    monkeypatch, system, location
):
    system[6]["nodes"][1]["locations"] = [location]
    with pytest.raises(ValueError, match="content reference unavailable"):
        call(monkeypatch, system, {"operation": "content-reference", "ref": "source"})


@pytest.mark.parametrize("operation", ["reference", "versions"])
def test_unknown_and_unauthorized_lookups_fail_identically(
    monkeypatch, system, operation
):
    system[6]["nodes"][1]["category"] = "category-3"
    for ref in ("source", "missing"):
        with pytest.raises(ValueError, match="document unavailable"):
            call(monkeypatch, system, {"operation": operation, "ref": ref})


def test_rejects_history_with_a_disallowed_version(monkeypatch, system):
    valid = system[6]["nodes"][1]
    restricted = deepcopy(valid)
    restricted["category"] = "category-3"
    monkeypatch.setattr(lookup, "versions_of", lambda *_: [restricted, valid])
    with pytest.raises(ValueError, match="history unavailable"):
        call(monkeypatch, system, {"operation": "versions", "ref": "source"})


def test_version_mac_must_belong_to_the_requested_document(monkeypatch, system):
    with pytest.raises(ValueError, match="document unavailable"):
        call(
            monkeypatch,
            system,
            {"operation": "reference", "ref": "project-reports", "mac": "2" * 64},
        )
    result = call(
        monkeypatch,
        system,
        {"operation": "reference", "ref": "source", "mac": "2" * 64},
    )
    assert result["result"]["urn"].endswith("/source")


@pytest.mark.parametrize(
    "payload",
    [
        {"operation": "versions", "ref": "source", "actor": "other"},
        {"operation": "versions", "ref": "source", "mac": "2" * 64},
        {"operation": "reference", "ref": "x" * 513},
        {"operation": "other", "ref": "source"},
    ],
)
def test_rejects_extra_authority_and_invalid_requests(monkeypatch, system, payload):
    with pytest.raises(ValueError):
        call(monkeypatch, system, payload)


def test_oversized_result_is_rejected(monkeypatch, system):
    monkeypatch.setattr(lookup, "MAX_SEARCH_RESPONSE_BYTES", 10)
    with pytest.raises(ValueError, match="exceeds limit"):
        call(monkeypatch, system, {"operation": "reference", "ref": "source"})


def test_protocol_returns_generic_denial_without_details(monkeypatch, system):
    monkeypatch.setattr(lookup, "resolve_peer_actor", lambda *_: "coordinator")
    system[6]["nodes"][1]["category"] = "category-3"
    connection = Connection(b'{"lookup":{"operation":"reference","ref":"source"}}\n')
    serve_connection(
        connection,
        identity_map="/protected/map",
        ledger=object(),
        org=system[2],
        make_plan=lambda _: None,
        load_search_manifest=lambda: system[6],
        search_guard=nullcontext,
    )
    assert json.loads(connection.response) == {"status": "rejected"}
