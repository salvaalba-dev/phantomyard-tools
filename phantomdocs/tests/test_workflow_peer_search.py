"""Peer search returns only authorized data and accepts no claimed identity."""

import sys
from contextlib import contextmanager
from copy import deepcopy

import pytest
import test_workflow_scan as fixtures
import yaml
from test_workflow_local_peer_protocol import Connection

from phantomdocs import workflow_peer_search as search
from phantomdocs.manifest import load, manifest_lock
from phantomdocs.workflow_local_peer_protocol import serve_connection


@pytest.fixture
def system():
    data = fixtures.system.__wrapped__()
    fixtures.index(data, category="category-3")
    return data


def call(monkeypatch, system, request, actor="coordinator"):
    monkeypatch.setattr(search, "resolve_peer_actor", lambda *_: actor)
    return search.search_peer(
        object(),
        request,
        identity_map="/protected/map",
        org=system[2],
        load_manifest=lambda: deepcopy(system[6]),
    )


def test_filters_confidential_nodes_before_returning_results(monkeypatch, system):
    response = call(monkeypatch, system, {"query": ""})
    assert response == {
        "status": "ok",
        "actor": "coordinator",
        "items": [{"kind": "folder", "urn": "urn:example-org:folder:project-reports"}],
    }
    assert call(monkeypatch, system, {"query": "source"})["items"] == []


def test_category_inheritance_uses_phantomorg(monkeypatch, system):
    system[2]["policies"]["security_categories"]["category-2-project"] = {
        "parent": "category-2"
    }
    system[6]["nodes"][1]["category"] = "category-2-project"
    assert len(call(monkeypatch, system, {"query": "source"})["items"]) == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"query": "", "actor": "other"},
        {"query": "", "category": "category-3"},
        {"query": None},
        {"query": "x" * (search.MAX_QUERY_BYTES + 1)},
        {},
    ],
)
def test_rejects_identity_and_context_overrides(monkeypatch, system, payload):
    with pytest.raises(ValueError):
        call(monkeypatch, system, payload)


def test_rejects_unmapped_actor_and_invalid_manifest(monkeypatch, system):
    with pytest.raises(ValueError):
        call(monkeypatch, system, {"query": ""}, actor="not-declared")
    system[6]["nodes"][0]["category"] = None
    with pytest.raises(ValueError):
        call(monkeypatch, system, {"query": ""})


def test_refuses_oversized_result_without_partial_disclosure(monkeypatch, system):
    monkeypatch.setattr(search, "MAX_SEARCH_RESPONSE_BYTES", 10)
    with pytest.raises(ValueError):
        call(monkeypatch, system, {"query": ""})


def test_protocol_authenticates_and_filters_before_sending(monkeypatch, system):
    import json

    monkeypatch.setattr(search, "resolve_peer_actor", lambda *_: "coordinator")
    connection = Connection(b'{"search":{"query":""}}\n')
    lock_state = []

    @contextmanager
    def guard():
        lock_state.append("locked")
        yield
        assert connection.response
        lock_state.append("released")

    serve_connection(
        connection,
        identity_map="/protected/map",
        ledger=object(),
        org=system[2],
        make_plan=lambda _: None,
        load_search_manifest=lambda: system[6],
        search_guard=guard,
    )
    result = json.loads(connection.response)
    assert result["status"] == "ok"
    assert result["items"] == [
        {"kind": "folder", "urn": "urn:example-org:folder:project-reports"}
    ]
    assert b"source" not in connection.response
    assert lock_state == ["locked", "released"]


def test_protocol_returns_generic_failure_if_search_is_unconfigured():
    connection = Connection(b'{"search":{"query":""}}\n')
    serve_connection(
        connection,
        identity_map="/protected/map",
        ledger=object(),
        org={},
        make_plan=lambda _: None,
    )
    assert connection.response == b'{"status":"rejected"}\n'


def test_guard_cleanup_failure_never_sends_a_second_response(monkeypatch, system):
    monkeypatch.setattr(search, "resolve_peer_actor", lambda *_: "coordinator")
    connection = Connection(b'{"search":{"query":""}}\n')

    @contextmanager
    def guard():
        yield
        raise OSError("synthetic unlock failure")

    serve_connection(
        connection,
        identity_map="/protected/map",
        ledger=object(),
        org=system[2],
        make_plan=lambda _: None,
        load_search_manifest=lambda: system[6],
        search_guard=guard,
    )
    assert connection.response.count(b"\n") == 1


@pytest.mark.skipif(sys.platform != "linux", reason="requires real flock")
def test_search_waits_for_concurrent_classification_change(
    monkeypatch, system, tmp_path
):
    import json
    import threading

    monkeypatch.setattr(search, "resolve_peer_actor", lambda *_: "coordinator")
    path = str(tmp_path / "manifest.yaml")
    system[6]["nodes"][1]["category"] = "category-2"
    (tmp_path / "manifest.yaml").write_text(yaml.safe_dump(system[6]), encoding="utf-8")
    connection = Connection(b'{"search":{"query":"source"}}\n')
    waiting = threading.Event()

    @contextmanager
    def guard():
        waiting.set()
        with manifest_lock(path):
            yield

    def query():
        serve_connection(
            connection,
            identity_map="/protected/map",
            ledger=object(),
            org=system[2],
            make_plan=lambda _: None,
            load_search_manifest=lambda: load(path),
            search_guard=guard,
        )

    with manifest_lock(path):
        thread = threading.Thread(target=query)
        thread.start()
        assert waiting.wait(5)
        assert not connection.response
        system[6]["nodes"][1]["category"] = "category-3"
        (tmp_path / "manifest.yaml").write_text(
            yaml.safe_dump(system[6]), encoding="utf-8"
        )
    thread.join(5)
    assert not thread.is_alive()
    assert json.loads(connection.response)["items"] == []
