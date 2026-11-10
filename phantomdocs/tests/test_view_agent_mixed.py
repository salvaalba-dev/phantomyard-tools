import base64
import json

import pytest

from phantomdocs.view_agent_mixed import MixedAgentGateMixin, validate_mixed_signers


def header(key):
    return "Nostr " + base64.b64encode(json.dumps({"pubkey": key}).encode()).decode()


class HumanGate:
    def issue_identified(self, authorization, origin, **context):
        return "human", authorization, context


class Gate(MixedAgentGateMixin, HumanGate):
    def __init__(self):
        self.mixed_agent_signers = {"agent": frozenset({"a" * 64})}

    def issue_scoped_agent(self, authorization, origin, **kwargs):
        if authorization != header("a" * 64):
            raise ValueError("Signature rejected")
        return "agent", kwargs


def test_mixed_route_keeps_human_path_and_selects_agent_signer():
    gate = Gate()
    assert (
        gate.issue_identified(header("b" * 64), "origin", persona="agent")[0] == "human"
    )
    assert gate.issue_identified(
        header("a" * 64), "origin", persona="agent", scope_id="agent-all"
    ) == ("agent", {"actor": "agent", "scope_id": "agent-all"})
    forged = (
        "Nostr "
        + base64.b64encode(
            json.dumps({"pubkey": "a" * 64, "sig": "invalid"}).encode()
        ).decode()
    )
    with pytest.raises(ValueError):
        gate.issue_identified(forged, "origin", persona="agent")


def test_mixed_signers_must_be_distinct_verified_route_subset():
    routes = [{"actor": "agent", "identities": ["a" * 64, "b" * 64]}]
    assert validate_mixed_signers({"agent": ["a" * 64]}, routes, {"agent"}) == {
        "agent": frozenset({"a" * 64})
    }
    for mapping in ({"agent": ["c" * 64]}, {"agent": ["a" * 64, "b" * 64]}):
        with pytest.raises(ValueError):
            validate_mixed_signers(mapping, routes, {"agent"})
