import copy

import pytest

from phantomdocs.view_projection_revalidate import revalidate_catalog


def inputs():
    resource = {
        "id": "old",
        "kind": "doc",
        "payload_sha256": "a" * 64,
        "requires": [],
        "endpoints": [],
        "scope": {"id": "project", "kind": "project"},
        "category": "category-4",
        "project": "project",
        "secret": False,
    }
    source = {"id": "old", "provenance": {"source_sha256": "b" * 64}}
    bundle = {
        "catalog": {
            "organization": "example",
            "authority_revision": "old",
            "resources": [resource],
        },
        "sources": [source],
    }
    draft = {
        "organization": "example",
        "resources": [resource | {"provenance": source["provenance"]}],
    }
    policy = {"scope_definitions": {"project": {"kind": "project"}}}
    return bundle, draft, policy, {"category-4": {}}, "new", "example"


def test_keeps_only_identical_approved_resources_without_mutating_history():
    args = inputs()
    original = copy.deepcopy(args[0])
    args[1]["resources"].append(args[1]["resources"][0] | {"id": "unapproved"})
    result = revalidate_catalog(*args)
    assert [row["id"] for row in result["resources"]] == ["old"]
    assert result["authority_revision"] == "new" and args[0] == original


@pytest.mark.parametrize("change", ["payload", "provenance", "category", "scope"])
def test_changed_or_revoked_source_and_classification_are_hidden(change):
    args = inputs()
    if change == "payload":
        args[1]["resources"][0]["payload_sha256"] = "f" * 64
    if change == "provenance":
        args[1]["resources"][0]["provenance"] = {"source_sha256": "c" * 64}
    if change == "category":
        args[3].clear()
    if change == "scope":
        args[2]["scope_definitions"].clear()
    assert revalidate_catalog(*args)["resources"] == []


def test_removes_dependent_resources_when_source_changes():
    args = inputs()
    dependent = copy.deepcopy(args[0]["catalog"]["resources"][0])
    dependent.update({"id": "dependent", "requires": ["old"]})
    args[0]["catalog"]["resources"].append(dependent)
    args[0]["sources"].append(
        {"id": "dependent", "provenance": {"source_sha256": "d" * 64}}
    )
    args[1]["resources"].append(dependent | {"provenance": {"source_sha256": "d" * 64}})
    args[1]["resources"][0]["payload_sha256"] = "f" * 64
    assert revalidate_catalog(*args)["resources"] == []


def test_rejects_other_organization_and_duplicate_ids():
    args = list(inputs())
    args[-1] = "other"
    with pytest.raises(ValueError):
        revalidate_catalog(*args)
    args = inputs()
    args[1]["resources"].append(copy.deepcopy(args[1]["resources"][0]))
    with pytest.raises(ValueError):
        revalidate_catalog(*args)
