"""Existing view-owned extensions are preserved, never interpreted as grants."""

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from phantomorg.spec.model import OrgSpec
from phantomorg.spec.shape_validator import ShapeError, validate_shape
from phantomorg.validator.graph import (
    EscalationCycleError,
    EscalationResponseError,
    check_no_cycles,
)

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


def test_response_must_close_an_escalation_path(document):
    document["escalation_matrix"] = [
        {"from": "ceo", "to": "project_lead", "condition": "test", "kind": "response"},
        {
            "from": "project_lead",
            "to": "ceo",
            "condition": "test",
        },
    ]
    validate_shape(document)
    check_no_cycles(OrgSpec.from_dict(document))
    document["escalation_matrix"][1]["kind"] = "coordination"
    with pytest.raises(EscalationResponseError):
        check_no_cycles(OrgSpec.from_dict(document))
    document["escalation_matrix"].pop()
    with pytest.raises(EscalationResponseError):
        check_no_cycles(OrgSpec.from_dict(document))


@pytest.mark.parametrize("kind", ["unknown", None])
def test_other_edge_kinds_still_detect_cycles(document, kind):
    document["escalation_matrix"] = [
        {
            "from": "ceo",
            "to": "project_lead",
            "condition": "test",
            "kind": kind,
        },
        {"from": "project_lead", "to": "ceo", "condition": "test"},
    ]
    with pytest.raises(EscalationCycleError):
        check_no_cycles(OrgSpec.from_dict(document))


def test_coordination_can_be_bidirectional_without_creating_escalation(document):
    document["escalation_matrix"] = [
        {
            "from": "ceo",
            "to": "project_lead",
            "condition": "test",
            "kind": "coordination",
        },
        {
            "from": "project_lead",
            "to": "ceo",
            "condition": "test",
            "kind": "coordination",
        },
    ]
    check_no_cycles(OrgSpec.from_dict(document))


def test_response_is_rendered_as_terminal_not_escalation(document, tmp_path):
    from phantomorg.compiler import build

    document["escalation_matrix"][0].pop("kind")
    document["escalation_matrix"].append(
        {
            "from": "ceo",
            "to": "project_lead",
            "condition": "close the case",
            "kind": "response",
        }
    )
    spec = OrgSpec.from_dict(document)
    check_no_cycles(spec)
    build(spec, tmp_path, only="marco")
    soul = (tmp_path / "marco" / "SOUL.md").read_text(encoding="utf-8")
    assert "close the case, responde a" in soul
    assert "close the case, escala a" not in soul


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
