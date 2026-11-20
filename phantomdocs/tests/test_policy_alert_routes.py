"""Direct destinations, mandatory email trace and no accidental group broadcast."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from phantomdocs import workflow_policy_alert_routes as routes


@pytest.fixture
def config():
    return {
        "schema_version": 1,
        "host": "example-host",
        "telegram_chat": "10001",
        "mail_to": "operator@example.invalid",
        "telegram_handler": "/opt/example/telegram-direct",
        "mail_handler": "/opt/example/mail-send",
    }


def test_primary_direct_telegram_and_email_trace_are_both_attempted(
    config, monkeypatch
):
    seen = []
    monkeypatch.setattr(
        routes,
        "_deliver",
        lambda handler, payload: seen.append((handler, payload)) or "provider:42",
    )
    ack = routes.route(
        config,
        {"schema_version": 1, "kind": "policy-unit-failed", "unit": "refresh.service"},
        state="timeout",
        now=datetime(2026, 11, 20, 15, 0, tzinfo=timezone.utc),
    )
    assert ack["delivered"] is True
    assert [p["recipient"] for _, p in seen] == ["10001", "operator@example.invalid"]
    assert all(
        p["message"]
        == "unit=refresh.service host=example-host state=timeout time=2026-11-20T15:00:00Z"
        for _, p in seen
    )


@pytest.mark.parametrize("failed", ["telegram", "email"])
def test_a_partial_failure_never_suppresses_the_other_route_or_claims_full_health(
    config, monkeypatch, failed
):
    seen = []

    def deliver(handler, payload):
        seen.append(payload["channel"])
        if payload["channel"] == failed:
            raise ValueError("unavailable")
        return "accepted:42"

    monkeypatch.setattr(routes, "_deliver", deliver)
    with pytest.raises(ValueError, match=failed):
        routes.route(
            config,
            {
                "schema_version": 1,
                "kind": "policy-unit-failed",
                "unit": "collect.service",
            },
            state="exit-code",
        )
    assert seen == ["telegram", "email"]


@pytest.mark.parametrize(
    "response",
    [
        '{"delivered":true,"recipient":"wrong-chat","receipt":"42"}',
        '{"delivered":true,"receipt":"42"}',
        "notify: telegram(text=1 voice=0)",
    ],
)
def test_broadcast_counts_and_wrong_recipient_are_not_accepted_as_direct_delivery(
    monkeypatch, response
):
    monkeypatch.setattr(routes, "protected_handler", lambda _: None)
    monkeypatch.setattr(
        routes.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout=response),
    )
    with pytest.raises(ValueError):
        routes._deliver("/protected/handler", {"recipient": "10001"})


@pytest.mark.parametrize("chat", ["-10001", "0", "10001\nother", "Teamup"])
def test_group_or_ambiguous_telegram_targets_are_refused(config, chat):
    config["telegram_chat"] = chat
    with pytest.raises(ValueError):
        routes.validate(config)


def test_event_cannot_override_the_reviewed_recipient(config):
    with pytest.raises(ValueError):
        routes.route(
            config,
            {
                "schema_version": 1,
                "kind": "policy-unit-failed",
                "unit": "refresh.service",
                "recipient": "other",
            },
            state="timeout",
        )
