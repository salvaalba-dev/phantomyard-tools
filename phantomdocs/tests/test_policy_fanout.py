"""Fanout orchestration, pending recovery and an independent drift watchdog."""

import copy
from contextlib import contextmanager

import pytest

from phantomdocs import workflow_bridge_policy as publisher
from phantomdocs import workflow_policy_watchdog as watchdog
from phantomdocs.workflow_policy_fanout import destinations


@pytest.fixture
def trial(monkeypatch):
    state = {
        "files": {
            "/source": b"version: 1\nnew: true\n",
            "/bridge": b"version: 1\nold: true\n",
            "/docs": b"version: 1\nolder: true\n",
        },
        "permissions": {
            "/bridge": {"uid": 0, "gid": 0, "mode": 0o600, "xattrs": {}},
            "/docs": {
                "uid": 0,
                "gid": 42,
                "mode": 0o640,
                "xattrs": {"system.posix_acl_access": "synthetic"},
            },
        },
        "pending": None,
        "active": True,
        "policy": False,
        "serial": False,
        "actions": [],
        "copies": [],
        "fail": None,
        "nested": False,
    }

    @contextmanager
    def guard(path, *, exclusive, recovering=False):
        key = "serial" if path.endswith(".publisher") else "policy"
        assert not state[key], "recursive lock would deadlock"
        if key == "policy" and state["pending"] and not recovering:
            raise ValueError("pending publication")
        state[key] = True
        try:
            yield
        finally:
            state[key] = False

    def read(path):
        assert state["policy"]
        return state["files"][path]

    def permissions(path):
        assert state["policy"]
        return copy.deepcopy(state["permissions"][path])

    def create(path, record):
        assert state["policy"] and state["pending"] is None
        state["pending"] = copy.deepcopy(record)

    def clear(path, record):
        assert state["policy"] and state["pending"] == record
        state["pending"] = None

    def sync(
        source, path, *, expected_source, expected_destination, expected_permissions
    ):
        assert state["policy"] and state["pending"] is not None
        assert state["files"][source] == expected_source
        assert state["files"][path] == expected_destination
        assert state["permissions"][path] == expected_permissions
        if state["fail"] == path:
            raise OSError("synthetic copy failure")
        state["files"][path] = expected_source
        state["copies"].append(path)

    def control(action, unit):
        assert state["serial"]
        state["actions"].append(action)
        if action == "is-active":
            return state["active"]
        if action == "stop":
            state["active"] = False
        else:
            assert not state["policy"], "ExecStartPre must acquire the policy lock"
            assert state["pending"] is not None
            if state["nested"]:
                run(prestart=True)
                assert state["pending"] is not None, "prestart erased restart intent"
            if state["fail"] == "start":
                raise RuntimeError("synthetic start failure")
            state["active"] = True
        return True

    monkeypatch.setattr(publisher, "policy_guard", guard)
    monkeypatch.setattr(watchdog, "policy_guard", guard)
    monkeypatch.setattr(publisher, "_read_policy", read)
    monkeypatch.setattr(watchdog, "_read_policy", read)
    monkeypatch.setattr(publisher, "policy_permissions", permissions)
    monkeypatch.setattr(publisher.fanout, "policy_permissions", permissions)
    monkeypatch.setattr(publisher.fanout, "ensure_independent", lambda _: None)
    monkeypatch.setattr(publisher.fanout, "read_pending", lambda _: state["pending"])
    monkeypatch.setattr(publisher.fanout, "create_pending", create)
    monkeypatch.setattr(publisher.fanout, "clear_pending", clear)
    monkeypatch.setattr(publisher, "_synchronize_locked", sync)
    monkeypatch.setattr(publisher, "_derive_both", lambda a, b, **kw: (a, b))
    monkeypatch.setattr(publisher, "_systemctl", control)
    return state


def run(**changes):
    kwargs = {
        "source": "/source",
        "destination": ["/bridge", "/docs"],
        "lock_path": "/lock",
        "node": "/usr/bin/node",
        "resolver": "/resolver.js",
        "unit": "bridge.service",
    }
    kwargs.update(changes)
    return publisher.refresh(**kwargs)


def test_all_destinations_share_lock_and_keep_distinct_permissions(trial):
    original_permissions = copy.deepcopy(trial["permissions"])
    assert run() == "restarted"
    assert (
        trial["files"]["/bridge"]
        == trial["files"]["/docs"]
        == trial["files"]["/source"]
    )
    assert trial["copies"] == ["/bridge", "/docs"]
    assert trial["permissions"] == original_permissions
    assert trial["pending"] is None
    assert trial["actions"] == ["is-active", "stop", "start"]
    assert run() == "synchronized"
    assert trial["copies"] == ["/bridge", "/docs"]


def test_second_failure_blocks_readers_then_timer_recovers_stopped_bridge(trial):
    trial["fail"] = "/docs"
    with pytest.raises(OSError, match="copy failure"):
        run()
    assert trial["files"]["/bridge"] == trial["files"]["/source"]
    assert trial["files"]["/docs"] != trial["files"]["/source"]
    assert trial["pending"] is not None and not trial["active"]
    with pytest.raises(ValueError, match="pending"):
        watchdog.check(
            source="/source", destination=["/bridge", "/docs"], lock_path="/lock"
        )
    trial["fail"] = None
    assert run() == "restarted"
    assert trial["copies"] == ["/bridge", "/docs"]
    assert trial["pending"] is None and trial["active"]


def test_failed_start_retains_restart_intent_and_nested_prestart_is_safe(trial):
    trial.update(fail="start", nested=True)
    with pytest.raises(RuntimeError, match="start failure"):
        run()
    assert trial["pending"] is not None and not trial["active"]
    trial["fail"] = None
    assert run() == "restarted"
    assert trial["copies"] == ["/bridge", "/docs"]
    assert trial["pending"] is None and trial["active"]


@pytest.mark.parametrize(
    "mutation", ["source", "content", "permissions", "order", "unit"]
)
def test_retry_rejects_changed_transaction_without_erasing_marker(trial, mutation):
    trial["fail"] = "/docs"
    with pytest.raises(OSError):
        run()
    record = copy.deepcopy(trial["pending"])
    trial["fail"] = None
    kwargs = {}
    if mutation == "source":
        trial["files"]["/source"] = b"version: 1\nthird: true\n"
    elif mutation == "content":
        trial["files"]["/docs"] = b"third state"
    elif mutation == "permissions":
        trial["permissions"]["/docs"]["gid"] = 99
    elif mutation == "order":
        kwargs["destination"] = ["/docs", "/bridge"]
    else:
        kwargs["unit"] = "other.service"
    with pytest.raises(ValueError, match="pending"):
        run(**kwargs)
    assert trial["pending"] == record
    assert trial["copies"] == ["/bridge"]


def test_foreign_pending_marker_is_never_adopted(trial):
    trial["pending"] = {"source": "/source", "destination": "/bridge"}
    with pytest.raises(ValueError, match="pending"):
        run()
    assert trial["pending"] == {"source": "/source", "destination": "/bridge"}
    assert trial["copies"] == []


def test_prestart_does_not_control_services(trial):
    assert run(prestart=True) == "synchronized"
    assert trial["actions"] == []
    assert trial["pending"] is None


@pytest.mark.parametrize("value", [None, [], "invalid"])
def test_corrupt_record_cannot_be_mistaken_for_absent_marker(monkeypatch, value):
    monkeypatch.setattr(publisher.fanout, "_json", lambda _: value)
    with pytest.raises(ValueError, match="invalid pending"):
        publisher.fanout.read_pending("/lock")


def test_cleanup_failure_does_not_strand_an_already_restarted_bridge(
    trial, monkeypatch
):
    clear = publisher.fanout.clear_pending

    def failed(*args):
        raise OSError("synthetic journal cleanup failure")

    monkeypatch.setattr(publisher.fanout, "clear_pending", failed)
    with pytest.raises(OSError, match="cleanup"):
        run()
    assert trial["active"] and trial["pending"] is not None
    monkeypatch.setattr(publisher.fanout, "clear_pending", clear)
    assert run() == "restarted"
    assert trial["pending"] is None


def test_secondary_drift_does_not_restart_unchanged_bridge(trial):
    trial["files"]["/bridge"] = trial["files"]["/source"]
    assert run() == "synchronized"
    assert trial["copies"] == ["/docs"]
    assert trial["actions"] == ["is-active"]


def test_inactive_service_is_not_enabled_by_publication(trial):
    trial["active"] = False
    assert run() == "synchronized"
    assert not trial["active"]
    assert trial["actions"] == ["is-active"]


def test_watchdog_reports_md5_drift_without_repair(trial):
    before = copy.deepcopy(trial["files"])
    result = watchdog.check(
        source="/source", destination=["/bridge", "/docs"], lock_path="/lock"
    )
    assert result["status"] == "drift"
    assert all(not item["matches"] for item in result["destinations"])
    assert len(result["source_md5"]) == 32
    assert trial["files"] == before and trial["pending"] is None
    run()
    assert (
        watchdog.check(
            source="/source", destination=["/bridge", "/docs"], lock_path="/lock"
        )["status"]
        == "ok"
    )


@pytest.mark.parametrize(
    "paths",
    [
        [],
        ["/source"],
        ["/bridge", "/bridge"],
        ["relative"],
        ["/x/../bridge"],
        ["/lock.pending"],
        ["/lock.publisher"],
    ],
)
def test_unsafe_or_duplicate_destinations_are_rejected(paths):
    with pytest.raises(ValueError):
        destinations("/source", paths, "/lock")


def test_repeated_cli_destinations(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(
        "sys.argv",
        [
            "publisher",
            "--source",
            "/source",
            "--destination",
            "/bridge",
            "--destination",
            "/docs",
            "--policy-lock",
            "/lock",
            "--resolver",
            "/resolver",
            "--unit",
            "bridge.service",
        ],
    )
    monkeypatch.setattr(
        publisher, "refresh", lambda **kw: calls.append(kw) or "synchronized"
    )
    publisher.main()
    assert calls[0]["destination"] == ["/bridge", "/docs"]
    assert "synchronized" in capsys.readouterr().out


@pytest.mark.parametrize("status,code", [("ok", 0), ("drift", 1), ("unavailable", 2)])
def test_watchdog_exit_codes(monkeypatch, capsys, status, code):
    monkeypatch.setattr(
        "sys.argv",
        [
            "watchdog",
            "--source",
            "/source",
            "--destination",
            "/bridge",
            "--policy-lock",
            "/lock",
        ],
    )

    def checked(**kw):
        if status == "unavailable":
            raise OSError("cannot read protected input")
        return {"status": status}

    monkeypatch.setattr(watchdog, "check", checked)
    with pytest.raises(SystemExit) as result:
        watchdog.main()
    assert result.value.code == code
    assert status in capsys.readouterr().out
