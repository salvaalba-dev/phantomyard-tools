"""Future actors require explicit preparation before automatic routing."""

import json

from test_view_agent_host import fixture
from test_view_agent_routes import baseline

from phantomdocs.view_agent_host import build_candidate
from phantomdocs.view_agent_onboarding import onboarding_report


def report(org, inventory, observe, directories=(), groups=(2001,)):
    candidate = json.loads(
        build_candidate(json.dumps(org).encode(), baseline(), inventory, observe)
    )
    return candidate, onboarding_report(org, inventory, candidate, groups, directories)


def test_future_actor_is_not_discovered_or_granted_from_org_alone():
    org, _inventory, _npub = fixture()

    def no_account_discovery(*_):
        raise AssertionError("Unknown accounts must not be queried")

    candidate, result = report(org, [], no_account_discovery)
    assert not candidate["agent_actors"]
    assert result["actors"] == [{"actor": "worker", "status": "not-provisioned"}]
    assert result["ready"] is False


def test_prepared_identity_still_requires_runtime_installation():
    org, inventory, npub = fixture()
    inventory[0]["route"].update(
        socket_path="/run/phantomview-worker/reader/link.sock", socket_group=2001
    )
    observe = lambda *_: (1002, npub)
    candidate, result = report(org, inventory, observe)
    assert candidate["agent_actors"] == ["worker"]
    assert result["actors"][0]["status"] == "runtime-not-prepared"
    assert not result["ready"]
    _, ready = report(org, inventory, observe, ["phantomview-worker/reader"])
    assert ready["ready"]
    _, missing_group = report(
        org, inventory, observe, ["phantomview-worker/reader"], []
    )
    assert not missing_group["ready"]
    # The diagnostic contains no public identity, signer or installation path.
    serialized = json.dumps(ready)
    assert npub not in serialized and inventory[0]["route"]["signer"] not in serialized
    assert "/run/" not in serialized


def test_withdrawal_cannot_be_overridden_by_a_prepared_inventory():
    org, inventory, _npub = fixture()
    org["actors"][0].pop("npub")
    candidate, result = report(org, inventory, lambda *_: None)
    assert not candidate["agent_actors"]
    assert result["actors"][0]["status"] == "no-declared-channel"


def test_mismatched_identity_cannot_be_reported_ready():
    org, inventory, _npub = fixture()
    candidate, result = report(org, inventory, lambda *_: (1002, None))
    assert not candidate["agent_actors"]
    assert result["actors"][0]["status"] == "identity-unverified"
    assert not result["ready"]
