"""Defaults come from the actual requester and catalog, never a global fallback."""

import copy
import subprocess
import sys

import pytest
import yaml

from phantommeet.request_defaults import RequestContextError, resolve_request


@pytest.fixture
def org() -> dict:
    return {
        "departments": [
            {"id": "operations", "name": "Operations"},
            {"id": "finance", "name": "Finance"},
            {"id": "training", "name": "Formación"},
        ],
        "roles": [
            {"id": "operator", "department": "operations"},
            {"id": "treasurer", "department": "finance"},
        ],
        "humans": [
            {
                "id": "organizer",
                "name": "Test Organizer",
                "role": "operator",
                "telegram_user_id": 101,
                "npub": "synthetic-key",
                "email": "organizer@example.invalid",
            },
            {
                "id": "delegate",
                "name": "Test Delegate",
                "role": "treasurer",
                "telegram_user_id": 202,
            },
        ],
        "actors": [
            {"id": "assistant", "role": "operator", "npub": "synthetic-actor-key"}
        ],
    }


@pytest.mark.parametrize(
    "channel,sender",
    [
        ("telegram", "101"),
        ("nostr", "synthetic-key"),
        ("email", "organizer@example.invalid"),
    ],
)
def test_requester_defaults_from_verified_channel(org, channel, sender):
    assert resolve_request(
        org, title="Weekly sync", sender_channel=channel, sender_id=sender
    ) == ("organizer", "operations")


def test_actor_uses_own_role_department(org):
    assert resolve_request(
        org,
        title="Weekly sync",
        sender_channel="nostr",
        sender_id="synthetic-actor-key",
    ) == ("assistant", "operations")


def test_explicit_requester_overrides_sender_and_uses_own_scope(org):
    assert resolve_request(
        org,
        title="Weekly sync",
        requester="delegate",
        sender_channel="telegram",
        sender_id="101",
    ) == ("delegate", "finance")


def test_explicit_destination_wins_over_title_and_scope(org):
    assert resolve_request(
        org,
        title="Finance and Operations",
        requester="organizer",
        department="training",
    ) == ("organizer", "training")


def test_unknown_explicit_department_never_falls_back(org):
    with pytest.raises(RequestContextError, match="unknown explicit"):
        resolve_request(
            org, title="Operations", requester="organizer", department="unknown"
        )


def test_title_can_supply_a_catalog_department_without_requester_scope(org):
    assert resolve_request(
        org, title="Session de FORMACION", requester="External organizer"
    ) == ("External organizer", "training")


def test_agreeing_title_and_scope_are_accepted(org):
    assert resolve_request(org, title="Operations weekly", requester="organizer") == (
        "organizer",
        "operations",
    )


@pytest.mark.parametrize("title", ["Finance weekly", "Finance and Operations"])
def test_conflicting_or_multiple_departments_require_question(org, title):
    with pytest.raises(RequestContextError, match="conflict|multiple"):
        resolve_request(org, title=title, requester="organizer")


def test_substrings_do_not_count_as_department_references(org):
    with pytest.raises(RequestContextError, match="ask for the department"):
        resolve_request(org, title="Financial report", requester="External organizer")


def test_different_unknown_requester_does_not_inherit_senders_scope(org):
    with pytest.raises(RequestContextError, match="ask for the department"):
        resolve_request(
            org,
            title="Weekly sync",
            requester="External organizer",
            sender_channel="telegram",
            sender_id="101",
        )


@pytest.mark.parametrize("sender", ["", "unknown", "@organizer", "organizer"])
def test_unknown_channel_identity_never_uses_display_name_or_persona(org, sender):
    with pytest.raises(RequestContextError, match="requester"):
        resolve_request(
            org, title="Operations", sender_channel="telegram", sender_id=sender
        )


def test_duplicate_channel_binding_requires_question(org):
    org["humans"][1]["telegram_user_id"] = 101
    with pytest.raises(RequestContextError, match="ambiguous"):
        resolve_request(
            org, title="Weekly sync", sender_channel="telegram", sender_id="101"
        )


def test_verified_external_sender_is_identified_without_inventing_scope(org):
    assert resolve_request(
        org, title="Operations meeting", sender_channel="telegram", sender_id="303"
    ) == ("telegram:303", "operations")
    with pytest.raises(RequestContextError, match="ask for the department"):
        resolve_request(
            org, title="Weekly sync", sender_channel="telegram", sender_id="303"
        )


def test_live_org_updates_are_used_instead_of_cached_persona_defaults(org):
    changed = copy.deepcopy(org)
    changed["roles"][0]["department"] = "finance"
    assert resolve_request(changed, title="Weekly sync", requester="organizer") == (
        "organizer",
        "finance",
    )


def test_control_characters_in_requester_are_rejected(org):
    with pytest.raises(RequestContextError, match="invalid requester"):
        resolve_request(org, title="Operations", requester="person\nfinance")


def test_cli_reads_org_and_outputs_only_normalized_fields(org, tmp_path):
    source = tmp_path / "org.yaml"
    source.write_text(yaml.safe_dump(org), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "phantommeet.request_defaults",
            "--org",
            str(source),
            "--title",
            "Weekly sync",
            "--sender-channel",
            "telegram",
            "--sender-id",
            "101",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["organizer", "operations"]
