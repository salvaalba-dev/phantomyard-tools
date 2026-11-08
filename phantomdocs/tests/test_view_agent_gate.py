import hashlib
import threading

import pytest
from test_view_agent_directory import HumanDirectory

from phantomdocs.view_agent_directory import AgentDirectory
from phantomdocs.view_agent_gate import AgentGateMixin

pytest_plugins = ["test_view_agent_directory"]


class Links:
    def issue(self, authorization, origin, expected):
        if authorization != "verified" or origin != expected:
            raise ValueError("Invalid signature")
        return expected + "/#c=" + "a" * 43


class HumanGate:
    def issue_identified(self, authorization, origin, **context):
        return (authorization, origin, context)


class Gate(AgentGateMixin, HumanGate):
    origin = "https://view.example"

    def __init__(self, directory):
        self.directory_loader = lambda: directory
        self.recipient_lock = threading.Lock()
        self.recipient_links = {}
        self.clock = lambda: 100

    def _prune_recipients(self):
        pass

    def issuer_links(self, actor):
        if actor != "agent":
            raise ValueError("Unknown route")
        return Links()

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()


def test_verified_link_is_bound_to_agent_scope_and_expires(org):
    directory = AgentDirectory(org, HumanDirectory(), frozenset({"agent"}))
    gate = Gate(directory)
    link = gate.issue_scoped_agent("verified", gate.origin, actor="agent", scope_id="river")
    recipient, expiry = gate.recipient_links[gate.digest(link.split("#c=")[1])]
    assert (recipient.persona, recipient.scope_id, recipient.human, expiry) == ("agent", "river", None, 400)
    with pytest.raises(ValueError):
        gate.issue_scoped_agent("verified", gate.origin, actor="agent", scope_id="river")


def test_invalid_signature_and_other_scope_create_no_binding(org):
    gate = Gate(AgentDirectory(org, HumanDirectory(), frozenset({"agent"})))
    with pytest.raises(ValueError):
        gate.issue_scoped_agent("invalid", gate.origin, actor="agent", scope_id="river")
    with pytest.raises(ValueError):
        gate.issue_scoped_agent("verified", gate.origin, actor="agent", scope_id="hill")
    assert not gate.recipient_links


def test_agent_route_uses_scope_and_other_routes_stay_unchanged(org):
    gate = Gate(AgentDirectory(org, HumanDirectory(), frozenset({"agent"})))
    result = gate.issue_identified("verified", gate.origin, persona="other", scope_id="river")
    assert result == ("verified", gate.origin, {"persona": "other", "scope_id": "river"})
    link = gate.issue_identified("verified", gate.origin, persona="agent", scope_id="river",
                                 sender="untrusted-display-value")
    recipient = gate.recipient_links[gate.digest(link.split("#c=")[1])][0]
    assert recipient.persona == "agent" and recipient.human is None
