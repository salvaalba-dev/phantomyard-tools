import copy
from types import SimpleNamespace

import pytest

from phantomdocs.view_agent_directory import ACTOR_SCOPE, AgentDirectory


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


def test_all_agent_scope_includes_authorized_resources_and_revokes(org):
    org["policies"]["security_categories"]["category-1"] = {}
    org["policies"]["access_levels"]["basic"]["categories"].append("category-1")
    org["policies"]["phantomview"]["scope_definitions"]["example"] = {
        "kind": "organization"
    }
    directory = AgentDirectory(org, HumanDirectory(), frozenset({"agent"}))
    recipient = directory.resolve_agent("agent", ACTOR_SCOPE)
    project = {
        "organization": "example",
        "scope": {"kind": "project", "id": "river"},
        "project": "river",
        "category": "category-4",
        "secret": False,
    }
    general = project | {
        "scope": {"kind": "organization", "id": "example"},
        "project": None,
        "category": "category-1",
    }
    assert directory.permits(recipient, project)
    assert directory.permits(recipient, general)
    assert not directory.allows_action(recipient, "resource.edit", ACTOR_SCOPE)
    changed = copy.deepcopy(org)
    changed["policies"]["phantomview"]["project_grants"]["agent"] = []
    changed["policies"]["access_levels"]["basic"]["categories"].remove("category-1")
    revoked = AgentDirectory(changed, HumanDirectory(), frozenset({"agent"}))
    with pytest.raises(ValueError):
        revoked.validate(recipient)
    current = revoked.resolve_agent("agent", ACTOR_SCOPE)
    assert not revoked.permits(current, project)
    assert not revoked.permits(current, general)
    changed["policies"]["phantomview"]["scope_definitions"][ACTOR_SCOPE] = {
        "kind": "organization"
    }
    ambiguous = AgentDirectory(changed, HumanDirectory(), frozenset({"agent"}))
    with pytest.raises(ValueError):
        ambiguous.resolve_agent("agent", ACTOR_SCOPE)


def test_aggregate_navigation_metadata_does_not_modify_human_policy(org):
    human = HumanDirectory()
    human.scope = SimpleNamespace(
        policy={
            "view_access": {
                "scope_definitions": {"river": {"kind": "project"}},
                "persona_scope_grants": {"agent": ["river"]},
            }
        }
    )
    directory = AgentDirectory(org, human, frozenset({"agent"}))
    policy = directory.scope.policy
    assert (
        policy["view_access"]["scope_definitions"][ACTOR_SCOPE]["kind"]
        == "organization"
    )
    assert ACTOR_SCOPE in policy["view_access"]["persona_scope_grants"]["agent"]
    assert ACTOR_SCOPE not in human.scope.policy["view_access"]["scope_definitions"]
    assert human.scope.policy["view_access"]["persona_scope_grants"]["agent"] == [
        "river"
    ]


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
