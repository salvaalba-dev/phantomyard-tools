"""Existing view-owned extensions are preserved, never interpreted as grants."""

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from phantomorg.spec.model import OrgSpec
from phantomorg.spec.shape_validator import ShapeError, validate_shape
from phantomorg.validator.graph import EscalationCycleError, check_no_cycles

ROOT = Path(__file__).parent.parent


@pytest.fixture
def document():
    doc = yaml.safe_load(
        (ROOT / "organizations/verdant-aquaponics/org.yaml").read_text(encoding="utf-8")
    )
    doc["organization"]["display_name"] = "Example"
    doc["humans"][0]["counterpart_persona"] = doc["actors"][0]["id"]
    doc["escalation_matrix"][0]["kind"] = "coordination"
    doc["policies"]["phantomview"] = {
        "scope_definitions": {"example": {"label": "Example"}},
        "persona_scope_grants": {},
        "human_action_grants": {},
        "project_grants": {},
    }
    return doc


def test_extensions_validate_and_survive_model_loading(document):
    validate_shape(document)
    schema = json.loads((ROOT / "phantomorg/spec/schema.json").read_text())
    jsonschema.validate(document, schema)
    spec = OrgSpec.from_dict(document)
    assert spec.organization.display_name == "Example"
    assert spec.humans[0].counterpart_persona == document["actors"][0]["id"]
    assert spec.escalation_matrix[0].kind == "coordination"
    assert spec.policies.phantomview == document["policies"]["phantomview"]


def test_edge_kind_does_not_bypass_cycle_detection(document):
    document["escalation_matrix"] = [
        {"from": "ceo", "to": "project_lead", "condition": "test", "kind": "response"},
        {
            "from": "project_lead",
            "to": "ceo",
            "condition": "test",
            "kind": "coordination",
        },
    ]
    validate_shape(document)
    with pytest.raises(EscalationCycleError):
        check_no_cycles(OrgSpec.from_dict(document))


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("organization", "display_name", []),
        ("human", "counterpart_persona", "../invalid"),
        ("escalation", "kind", 1),
        ("policies", "phantomview", []),
        ("policies", "unknown_policy", {}),
    ],
)
def test_invalid_extension_is_rejected(document, section, key, value):
    target = {
        "organization": document["organization"],
        "human": document["humans"][0],
        "escalation": document["escalation_matrix"][0],
        "policies": document["policies"],
    }[section]
    target[key] = value
    with pytest.raises(ShapeError):
        validate_shape(document)
