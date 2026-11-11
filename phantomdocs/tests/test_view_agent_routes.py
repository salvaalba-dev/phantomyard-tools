import copy

import pytest

from phantomdocs.view_agent_routes import compose_routes


def baseline():
    return {
        "actor": "chief",
        "issuer_uid": 1001,
        "socket_path": "/run/chief.sock",
        "socket_group": 2001,
        "identities": ["a" * 64],
        "conversation_socket": "/run/conversation.sock",
        "additional_issuers": [],
    }


def route(actor="chief", uid=1001, path="/run/chief.sock", signer="b" * 64):
    return {
        "actor": actor,
        "issuer_uid": uid,
        "socket_path": path,
        "socket_group": 2001,
        "signer": signer,
    }


def test_mixed_and_new_route_then_removal_preserve_human_baseline():
    base = baseline()
    original = copy.deepcopy(base)
    other = route("worker", 1002, "/run/worker.sock", "c" * 64)
    composed = compose_routes(base, [other, route()])
    assert base == original
    assert composed["identities"] == ["a" * 64, "b" * 64]
    assert composed["mixed_agent_signers"] == {"chief": ["b" * 64]}
    assert composed["agent_actors"] == ["chief", "worker"]
    assert composed["additional_issuers"][0]["conversation_socket"] is None
    removed = compose_routes(base, [])
    assert removed["identities"] == ["a" * 64]
    assert removed["conversation_socket"] == "/run/conversation.sock"
    assert removed["additional_issuers"] == []
    assert removed["agent_actors"] == []


def test_ambiguous_shared_identity_uid_and_socket_are_denied():
    with pytest.raises(ValueError):
        compose_routes(baseline(), [route(uid=9999)])
    with pytest.raises(ValueError):
        compose_routes(baseline(), [route(signer="a" * 64)])
    with pytest.raises(ValueError):
        compose_routes(
            baseline(), [route(), route("worker", 1001, "/run/worker.sock", "c" * 64)]
        )
    with pytest.raises(ValueError):
        compose_routes(baseline(), [route("worker", 1002, "/run/chief.sock", "c" * 64)])


def test_managed_state_cannot_be_reused_as_human_baseline():
    with pytest.raises(ValueError):
        compose_routes(compose_routes(baseline(), [route()]), [])
