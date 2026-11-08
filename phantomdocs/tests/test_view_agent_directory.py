import copy

import pytest

from phantomdocs.view_agent_directory import AgentDirectory


class HumanDirectory:
    scope = object()
    authority_revision = "synthetic"

    def validate(self, recipient):
        return recipient

    def permits(self, recipient, resource):
        return recipient == "human" and resource == "allowed"

    def allows_action(self, recipient, action, scope_id, **kwargs):
        return recipient == "human" and action == "allowed"


@pytest.fixture
def org():
    return {
        "version": 1,
        "organization": {"id": "example"},
        "actors": [{"id": "agent", "role": "lead", "actor_exceptions": []}],
        "roles": [{"id": "lead", "access_level": "basic", "security_exceptions": []}],
        "policies": {
            "access_levels": {"basic": {"categories": ["category-4"]}},
            "security_categories": {
                "category-4": {"scope": "project", "owner": "river"}
            },
            "phantomview": {
                "scope_definitions": {"river": {"kind": "project"}},
                "persona_scope_grants": {"agent": ["river"]},
                "project_grants": {"agent": ["river"]},
            },
        },
    }


def test_actor_scope_and_human_route_are_separate(org):
    directory = AgentDirectory(org, HumanDirectory(), frozenset({"agent"}))
    recipient = directory.resolve_agent("agent", "river")
    resource = {
        "organization": "example",
        "scope": {"kind": "project", "id": "river"},
        "project": "river",
        "category": "category-4",
        "secret": False,
    }
    assert recipient.human is None
    assert directory.permits(recipient, resource)
    assert not directory.allows_action(recipient, "resource.edit", "river")
    assert directory.permits("human", "allowed")
    assert directory.allows_action("human", "allowed", "river")


def test_scope_and_policy_revocations_invalidate_sessions(org):
    directory = AgentDirectory(org, HumanDirectory(), frozenset({"agent"}))
    recipient = directory.resolve_agent("agent", "river")
    changed = copy.deepcopy(org)
    changed["policies"]["phantomview"]["persona_scope_grants"]["agent"] = []
    revoked = AgentDirectory(changed, HumanDirectory(), frozenset({"agent"}))
    with pytest.raises(ValueError):
        revoked.validate(recipient)
    with pytest.raises(ValueError):
        revoked.resolve_agent("agent", "river")
    with pytest.raises(ValueError):
        AgentDirectory(org, HumanDirectory(), frozenset()).resolve_agent(
            "agent", "river"
        )


def test_multiple_agents_use_same_rules_with_disjoint_scopes(org):
    org["actors"].append({"id": "other", "role": "lead", "actor_exceptions": []})
    view = org["policies"]["phantomview"]
    view["scope_definitions"]["hill"] = {"kind": "project"}
    view["persona_scope_grants"]["other"] = ["hill"]
    view["project_grants"]["other"] = ["hill"]
    directory = AgentDirectory(org, HumanDirectory(), frozenset({"agent", "other"}))
    first = directory.resolve_agent("agent", "river")
    second = directory.resolve_agent("other", "hill")
    assert first.scope_id == "river"
    assert second.scope_id == "hill"
    assert directory.scope.can_enter(None, "agent", "river")
    assert not directory.scope.can_enter(None, "agent", "hill")
    with pytest.raises(ValueError):
        directory.resolve_agent("agent", "hill")
    with pytest.raises(ValueError):
        directory.resolve_agent("other", "river")
