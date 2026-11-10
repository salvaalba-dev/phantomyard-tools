"""Account correspondence is descriptive, validated, and never a permission."""

import copy
from pathlib import Path

import jsonschema
import pytest
import yaml
from phantomorg.spec.model import OrgSpec
from phantomorg.spec.shape_validator import ShapeError, validate_shape

ORG = Path(__file__).parent.parent / "organizations/verdant-aquaponics/org.yaml"


@pytest.fixture
def document():
    doc = yaml.safe_load(ORG.read_text(encoding="utf-8"))
    doc["email_correspondence"] = [
        {"email": "personal@example.org", "humans": [doc["humans"][0]["id"]]},
        {"email": "shared@example.org", "humans": [doc["humans"][0]["id"]],
         "actors": [doc["actors"][0]["id"]]},
    ]
    return doc


def test_correspondence_is_loaded_without_changing_existing_identity(document):
    validate_shape(document)
    spec = OrgSpec.from_dict(document)
    assert spec.email_correspondence[1].actors == [document["actors"][0]["id"]]
    assert spec.humans[0].email == document["humans"][0].get("email")


def test_schema_accepts_correspondence(document):
    import json

    schema = json.loads((ORG.parents[2] / "phantomorg/spec/schema.json").read_text())
    jsonschema.validate(document, schema)


@pytest.mark.parametrize("entry", [
    {"email": "bad", "humans": ["mar"]},
    {"email": "valid@example.org"},
    {"email": "valid@example.org", "humans": ["unknown"]},
    {"email": "valid@example.org", "actors": ["unknown"]},
    {"email": "valid@example.org", "humans": ["mar", "mar"]},
    {"email": "valid@example.org", "actors": "marco"},
    {"email": "valid@example.org", "humans": ["mar"], "grant": True},
])
def test_invalid_entries_fail_closed(document, entry):
    document["email_correspondence"] = [entry]
    with pytest.raises(ShapeError):
        validate_shape(document)


def test_duplicate_addresses_are_rejected_case_insensitively(document):
    duplicate = copy.deepcopy(document["email_correspondence"][0])
    duplicate["email"] = duplicate["email"].upper()
    document["email_correspondence"].append(duplicate)
    with pytest.raises(ShapeError):
        validate_shape(document)
