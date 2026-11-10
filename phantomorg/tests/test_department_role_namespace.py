"""Only a role and its own department may share an identifier."""

import copy
from pathlib import Path

import yaml

from phantomorg.compiler.scopes import derive_scopes
from phantomorg.spec.model import OrgSpec
from phantomorg.spec.shape_validator import validate_shape
from phantomorg.validator.refs import check_references

ROOT = Path(__file__).parent.parent


def example():
    doc = yaml.safe_load(
        (ROOT / "organizations/verdant-aquaponics/org.yaml").read_text(encoding="utf-8")
    )
    role = doc["roles"][0]
    department_id = role["department"]
    old_role = role["id"]
    role["id"] = department_id
    for actor in doc["actors"]:
        if actor["role"] == old_role:
            actor["role"] = department_id
    for entry in doc["escalation_matrix"]:
        for key in ("from", "to"):
            if entry[key] == old_role:
                entry[key] = department_id
    for other in doc["roles"]:
        if other.get("reports_to") == old_role:
            other["reports_to"] = department_id
    return doc


def collisions(doc):
    validate_shape(doc)
    return [
        error
        for error in check_references(OrgSpec.from_dict(doc))
        if "collides" in error
    ]


def test_role_can_share_own_department_identifier():
    assert not collisions(example())


def test_role_cannot_share_unrelated_department_identifier():
    doc = example()
    doc["roles"][0]["department"] = next(
        d["id"] for d in doc["departments"] if d["id"] != doc["roles"][0]["id"]
    )
    assert collisions(doc)


def test_actor_and_human_collisions_remain_errors():
    doc = example()
    doc["actors"][0]["id"] = doc["roles"][0]["id"]
    doc["humans"][0]["id"] = doc["roles"][0]["id"]
    errors = collisions(doc)
    assert any("actors:" in error for error in errors)
    assert any("humans:" in error for error in errors)


def test_typed_department_and_role_preserve_scope_resolution():
    doc = example()
    separate = copy.deepcopy(doc)
    shared = doc["roles"][0]["id"]
    for dept in separate["departments"]:
        if dept["id"] == shared:
            dept["id"] = "separate_department"
        if dept.get("parent") == shared:
            dept["parent"] = "separate_department"
    for role in separate["roles"]:
        if role["department"] == shared:
            role["department"] = "separate_department"
    shared_spec = OrgSpec.from_dict(doc)
    assert shared_spec.role_by_id(shared).department == shared
    assert shared_spec.department_by_id(shared).id == shared
    for rule in ("chain", "department"):
        assert derive_scopes(shared_spec, rule) == derive_scopes(
            OrgSpec.from_dict(separate), rule
        )
