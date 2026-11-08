import copy

import pytest

from phantomdocs.view_agent_scope import permits_view


@pytest.fixture
def scenario():
    org = {
        "version": 1,
        "organization": {"id": "example"},
        "actors": [{"id": "agent", "role": "lead", "actor_exceptions": []}],
        "roles": [{"id": "lead", "access_level": "basic", "security_exceptions": []}],
        "policies": {
            "access_levels": {"basic": {"categories": ["category-4"]}},
            "security_categories": {
                "category-0": {},
                "category-4": {"scope": "project"},
                "category-4-river": {
                    "scope": "project",
                    "owner": "river",
                    "parent": "category-4",
                },
                "category-4-hill": {
                    "scope": "project",
                    "owner": "hill",
                    "parent": "category-4",
                },
            },
            "phantomview": {
                "scope_definitions": {
                    "river": {"kind": "project"},
                    "hill": {"kind": "project"},
                },
                "persona_scope_grants": {"agent": ["river"]},
                "project_grants": {"agent": ["river"]},
            },
        },
    }
    resource = {
        "organization": "example",
        "secret": False,
        "category": "category-4-river",
        "scope": {"id": "river", "kind": "project"},
        "project": "river",
    }
    return org, resource


def test_agent_project_grant_inherits_category_without_human(scenario):
    org, resource = scenario
    assert permits_view(org, "agent", resource)


def test_actor_scope_combines_organization_and_authorized_projects(scenario):
    org, project = copy.deepcopy(scenario)
    policy = org["policies"]
    policy["security_categories"]["category-1"] = {}
    policy["access_levels"]["basic"]["categories"].append("category-1")
    policy["phantomview"]["scope_definitions"]["example"] = {"kind": "organization"}
    general = project | {
        "scope": {"id": "example", "kind": "organization"},
        "project": None,
        "category": "category-1",
    }
    assert not permits_view(org, "agent", general)
    assert permits_view(org, "agent", general, actor_scope=True)
    assert permits_view(org, "agent", project, actor_scope=True)
    other = copy.deepcopy(project)
    other["scope"]["id"] = other["project"] = "hill"
    other["category"] = "category-4-hill"
    assert not permits_view(org, "agent", other, actor_scope=True)
    policy["phantomview"]["project_grants"]["agent"] = []
    assert not permits_view(org, "agent", project, actor_scope=True)
    policy["access_levels"]["basic"]["categories"].remove("category-1")
    assert not permits_view(org, "agent", general, actor_scope=True)


def test_actor_scope_still_requires_explicit_department_grant(scenario):
    org, resource = copy.deepcopy(scenario)
    org["departments"] = [{"id": "operations"}]
    org["policies"]["phantomview"]["scope_definitions"]["operations"] = {
        "kind": "department"
    }
    resource.update(scope={"id": "operations", "kind": "department"}, project=None)
    org["policies"]["security_categories"]["category-1"] = {}
    org["policies"]["access_levels"]["basic"]["categories"].append("category-1")
    resource["category"] = "category-1"
    assert not permits_view(org, "agent", resource, actor_scope=True)
    org["policies"]["phantomview"]["persona_scope_grants"]["agent"].append("operations")
    assert permits_view(org, "agent", resource, actor_scope=True)


@pytest.mark.parametrize(
    "change", ["other_project", "other_category", "secret", "unknown_actor", "revoke"]
)
def test_fails_closed_for_scope_category_secret_and_revocation(scenario, change):
    org, resource = copy.deepcopy(scenario)
    actor = "agent"
    if change == "other_project":
        resource["scope"]["id"] = resource["project"] = "hill"
    elif change == "other_category":
        resource["category"] = "category-4-hill"
    elif change == "secret":
        resource["secret"] = True
    elif change == "unknown_actor":
        actor = "unknown"
    else:
        org["policies"]["phantomview"]["persona_scope_grants"]["agent"] = []
    assert not permits_view(org, actor, resource)
