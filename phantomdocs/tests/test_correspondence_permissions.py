"""Descriptive correspondence must never change document authorization."""

import copy
from pathlib import Path

import yaml

from phantomdocs.access import can_read, can_write


def test_correspondence_does_not_change_access():
    org_file = (
        Path(__file__).parents[2]
        / "phantomorg/organizations/verdant-aquaponics/org.yaml"
    )
    org = yaml.safe_load(org_file.read_text(encoding="utf-8"))
    changed = copy.deepcopy(org)
    changed["email_correspondence"] = [
        {
            "email": "shared@example.org",
            "humans": [org["humans"][0]["id"]],
            "actors": [org["actors"][0]["id"]],
        }
    ]
    for actor in [a["id"] for a in org["actors"]] + ["unknown"]:
        for category in org["policies"]["security_categories"]:
            assert can_read(org, actor, category) == can_read(changed, actor, category)
            for owners in ([], [actor], ["unknown"]):
                assert can_write(org, actor, category, owners) == can_write(
                    changed, actor, category, owners
                )
