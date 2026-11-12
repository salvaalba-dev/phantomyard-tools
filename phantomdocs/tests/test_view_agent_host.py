import copy
import json

import pytest
from test_view_agent_routes import baseline, route

from phantomdocs.signing import npub_encode
from phantomdocs.view_agent_host import build_candidate


def fixture():
    npub = npub_encode("11" * 32)
    org = {
        "version": 1,
        "organization": {"id": "example"},
        "actors": [{"id": "worker", "npub": npub}],
    }
    inventory = [
        {
            "actor": "worker",
            "account": "agent_account",
            "persona": "worker",
            "route": route("worker", 1002, "/run/worker.sock", "c" * 64),
        }
    ]
    return org, inventory, npub


def build(org, inventory, observe):
    return json.loads(
        build_candidate(json.dumps(org).encode(), baseline(), inventory, observe)
    )


def test_verified_addition_and_org_removal_preserve_human_route():
    org, inventory, npub = fixture()
    original = copy.deepcopy(inventory)
    result = build(org, inventory, lambda *_: (1002, npub))
    assert result["agent_actors"] == ["worker"]
    assert result["identities"] == baseline()["identities"]
    assert result["conversation_socket"] == baseline()["conversation_socket"]
    org["actors"] = []

    def must_not_probe(*_):
        raise AssertionError("A removed actor must not require a runtime query")

    result = build(org, inventory, must_not_probe)
    assert result["agent_actors"] == [] and result["additional_issuers"] == []
    assert inventory == original


def test_identity_change_and_uid_reuse_cannot_retain_a_route():
    org, inventory, _npub = fixture()
    other = npub_encode("22" * 32)
    result = build(org, inventory, lambda *_: (1002, other))
    assert result["agent_actors"] == []
    with pytest.raises(ValueError, match="Unix identity"):
        build(org, inventory, lambda *_: (1003, other))


def test_identity_query_failure_cannot_produce_candidate():
    org, inventory, _npub = fixture()

    def failed(*_):
        raise TimeoutError("Runtime unavailable")

    with pytest.raises(TimeoutError):
        build(org, inventory, failed)


def test_shared_public_identity_cannot_select_multiple_actors():
    org, inventory, npub = fixture()
    org["actors"].append({"id": "other", "npub": npub})
    with pytest.raises(ValueError, match="multiple organization actors"):
        build(org, inventory, lambda *_: (1002, npub))
