from contextlib import nullcontext

import pytest

from phantomdocs import workflow_bridge_policy as module


@pytest.fixture
def harness(monkeypatch):
    files = {"source": b"new", "dest": b"old"}
    actions = []
    monkeypatch.setattr(module, "policy_guard", lambda *a, **k: nullcontext())
    monkeypatch.setattr(module.os.path, "lexists", lambda _: False)
    monkeypatch.setattr(module, "_read_policy", lambda path: files[path])
    monkeypatch.setattr(module, "parse_policy", lambda _: {})
    monkeypatch.setattr(module, "_derive_both", lambda *a, **k: ({"x": 1}, {"x": 0}))

    def sync(src, dst, *, expected_source, expected_destination):
        assert files[src] == expected_source and files[dst] == expected_destination
        files[dst] = files[src]
        actions.append("sync")

    def systemctl(action, unit):
        assert unit == "bridge.service"
        actions.append(action)
        return True

    monkeypatch.setattr(module, "_synchronize_locked", sync)
    monkeypatch.setattr(module, "_systemctl", systemctl)
    return files, actions


def run_refresh(**kw):
    return module.refresh(
        source="source",
        destination="dest",
        lock_path="lock",
        node="node",
        resolver="resolver",
        unit="bridge.service",
        **kw,
    )


def test_changed_policy_stops_syncs_then_starts(harness):
    files, actions = harness
    assert run_refresh() == "restarted"
    assert files["dest"] == b"new"
    assert actions == ["is-active", "stop", "sync", "start"]


def test_unrelated_policy_change_does_not_restart(harness, monkeypatch):
    _, actions = harness
    monkeypatch.setattr(module, "_derive_both", lambda *a, **k: ({"x": 1}, {"x": 1}))
    assert run_refresh() == "synchronized"
    assert actions == ["is-active", "sync"]


def test_prestart_never_controls_service(harness):
    _, actions = harness
    assert run_refresh(prestart=True) == "synchronized"
    assert actions == ["sync"]


@pytest.mark.parametrize("failure", ["pending", "invalid", "sync"])
def test_failures_leave_active_bridge_stopped(harness, monkeypatch, failure):
    _, actions = harness
    if failure == "pending":
        monkeypatch.setattr(module.os.path, "lexists", lambda _: True)
    elif failure == "invalid":

        def fail(*args, **kwargs):
            raise module.BridgeRefreshError("invalid")

        monkeypatch.setattr(module, "_derive_both", fail)
    else:

        def fail(*args, **kwargs):
            raise module.BridgeRefreshError("sync failed")

        monkeypatch.setattr(module, "_synchronize_locked", fail)
    with pytest.raises(module.BridgeRefreshError):
        run_refresh()
    assert actions.count("stop") == 1
    assert "start" not in actions


def test_identical_policy_does_not_restart_or_write(harness, monkeypatch):
    files, actions = harness
    files["dest"] = files["source"]
    monkeypatch.setattr(module, "_derive_both", lambda *a, **k: ({"x": 1}, {"x": 1}))
    assert run_refresh() == "synchronized"
    assert actions == ["is-active"]


def test_inactive_bridge_is_not_started(harness, monkeypatch):
    _, actions = harness

    def control(action, unit):
        actions.append(action)
        return action != "is-active"

    monkeypatch.setattr(module, "_systemctl", control)
    assert run_refresh() == "synchronized"
    assert actions == ["is-active", "sync"]


def test_uncertain_service_state_attempts_stop(harness, monkeypatch):
    _, actions = harness

    def control(action, unit):
        actions.append(action)
        if action == "is-active":
            raise module.BridgeRefreshError("uncertain")
        return True

    monkeypatch.setattr(module, "_systemctl", control)
    with pytest.raises(module.BridgeRefreshError):
        run_refresh()
    assert actions == ["is-active", "stop"]


def test_source_change_during_sync_leaves_bridge_stopped(harness, monkeypatch):
    files, actions = harness

    def changed(src, dst, **kw):
        actions.append("sync")
        files[dst] = files[src]
        files[src] = b"changed-again"

    monkeypatch.setattr(module, "_synchronize_locked", changed)
    with pytest.raises(module.BridgeRefreshError, match="changed"):
        run_refresh()
    assert actions == ["is-active", "stop", "sync"]


def test_strict_yaml_failure_stops_active_bridge(harness, monkeypatch):
    _, actions = harness

    def invalid(_):
        raise ValueError("duplicate policy key")

    monkeypatch.setattr(module, "parse_policy", invalid)
    with pytest.raises(ValueError):
        run_refresh()
    assert actions == ["is-active", "stop"]


def test_stopped_service_is_not_restarted_when_sync_fails(harness, monkeypatch):
    _, actions = harness

    def fail(*args, **kwargs):
        raise module.BridgeRefreshError("sync failure")

    monkeypatch.setattr(module, "_synchronize_locked", fail)
    with pytest.raises(module.BridgeRefreshError):
        run_refresh()
    assert actions == ["is-active", "stop"]


def test_linux_real_lock_sync_and_resolver(monkeypatch):
    import os
    import tempfile
    from pathlib import Path

    from phantomdocs.signing import npub_encode

    resolver = os.environ.get("PHANTOMBRIDGE_TEST_RESOLVER")
    if os.name != "posix" or getattr(os, "geteuid", lambda: -1)() != 0 or not resolver:
        pytest.skip("requires a protected Linux resolver and root")
    template = "version: 1\nroles: [{{id: role, reports_to: null}}]\nactors: [{{id: agent, role: role, npub: {}}}]\nescalation_matrix: []\n"
    with tempfile.TemporaryDirectory(dir="/root") as trial:
        source, dest, lock = (Path(trial) / n for n in ("source", "dest", "lock"))
        source.write_text(template.format(npub_encode("11" * 32)))
        dest.write_text(template.format(npub_encode("22" * 32)))
        lock.touch(mode=0o600)
        actions = []
        monkeypatch.setattr(
            module, "_systemctl", lambda action, unit: actions.append(action) or True
        )
        result = module.refresh(
            source=str(source),
            destination=str(dest),
            lock_path=str(lock),
            node="/usr/bin/node",
            resolver=resolver,
            unit="synthetic.service",
        )
        assert result == "restarted"
        assert source.read_bytes() == dest.read_bytes()
        assert actions == ["is-active", "stop", "start"]
