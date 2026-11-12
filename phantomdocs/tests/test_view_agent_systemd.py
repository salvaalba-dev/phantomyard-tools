from contextlib import contextmanager

import pytest

from phantomdocs.view_agent_systemd import SystemdRouteHost


def host(**overrides):
    args = {
        "org": "/safe/org",
        "config": "/safe/config",
        "journal": "/safe/pending",
        "committed": "/safe/committed",
        "policy_lock": "/safe/policy.lock",
        "transaction_lock": "/safe/transaction.lock",
        "unit": "viewer.service",
        "validate": lambda _candidate: None,
        "health": lambda: True,
    }
    return SystemdRouteHost(**(args | overrides))


def test_rejects_ambiguous_paths_and_invalid_unit():
    with pytest.raises(ValueError):
        host(journal="/safe/config")
    with pytest.raises(ValueError):
        host(unit="viewer.service;danger")
    with pytest.raises(ValueError):
        host(config="/safe/../elsewhere")


def test_false_validation_result_is_rejected():
    viewer = host(validate=lambda _: False)
    with pytest.raises(ValueError):
        viewer.validate(b"candidate")


def test_lock_order_and_sharing(monkeypatch):
    events = []

    @contextmanager
    def lock(path, *, exclusive):
        events.append((path, exclusive))
        yield

    monkeypatch.setattr("phantomdocs.view_agent_systemd.policy_guard", lock)
    with host().lock():
        assert events == [
            ("/safe/transaction.lock", True),
            ("/safe/policy.lock", False),
        ]


def test_service_control_is_bounded_and_health_must_pass(monkeypatch):
    calls = []
    ticks = iter([0, 20])
    monkeypatch.setattr(
        "phantomdocs.view_agent_systemd.time.monotonic", lambda: next(ticks)
    )

    def run(args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr("phantomdocs.view_agent_systemd.subprocess.run", run)
    viewer = host(health=lambda: False)
    viewer.stop()
    viewer.start()
    assert not viewer.healthy()
    assert [item[0][-2:] for item in calls] == [
        ["stop", "viewer.service"],
        ["start", "viewer.service"],
        ["is-active", "viewer.service"],
    ]
    assert all(item[1]["timeout"] == 30 and item[1]["check"] for item in calls)


def test_delayed_reader_readiness_is_allowed_within_deadline(monkeypatch):
    observations = iter([False, False, True])
    pauses = []
    monkeypatch.setattr(
        "phantomdocs.view_agent_systemd.subprocess.run", lambda *a, **k: None
    )
    monkeypatch.setattr("phantomdocs.view_agent_systemd.time.monotonic", lambda: 0)
    monkeypatch.setattr("phantomdocs.view_agent_systemd.time.sleep", pauses.append)
    viewer = host(health=lambda: next(observations))
    assert viewer.healthy()
    assert pauses == [0.25, 0.25]


@pytest.mark.parametrize("interval", [0, 61, True, 1.5])
def test_unbounded_readiness_interval_is_rejected(interval):
    with pytest.raises(ValueError):
        host(readiness_seconds=interval)
