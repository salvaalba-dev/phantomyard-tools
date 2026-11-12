"""Exercise the real CLI and transaction engine with a running synthetic viewer."""

import copy
import json
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from test_view_agent_supervisor import Host

from phantomdocs import view_agent_host as module


@pytest.fixture
def cli(monkeypatch):
    settings = {
        key: "/etc/example/" + key
        for key in (
            "org",
            "config",
            "journal",
            "committed",
            "policy_lock",
            "transaction_lock",
            "baseline",
            "inventory",
            "runtime",
            "python",
            "reader",
        )
    }
    settings.update(unit="example-reader.service", supplementary_groups=[2001])

    class CliHost(Host):
        locked = False
        options = None

        @contextmanager
        def lock(self):
            self.locked = True
            try:
                yield
            finally:
                self.locked = False

        def validate(self, data):
            self.options["validate"](data)

        def healthy(self):
            return self.running and self.options["health"]()

    host = CliHost()
    state = SimpleNamespace(
        host=host,
        baseline={"port": 8789},
        baseline_reads=[],
        health_ports=[],
        builds=[],
        validations=[],
        candidate=b"old",
    )

    def read(path):
        if path == "/etc/example/settings.json":
            return settings
        if path == settings["baseline"]:
            state.baseline_reads.append(host.locked)
            if isinstance(state.baseline, Exception):
                raise state.baseline
            return copy.deepcopy(state.baseline)
        assert path == settings["inventory"]
        return []

    def adapter(**options):
        host.options = options
        return host

    def build(*args):
        state.builds.append(args)
        return state.candidate

    def health(port):
        state.health_ports.append(port)
        return True

    def run(*, apply=True, onboarding=False):
        arguments = ["supervisor", "--settings", "/etc/example/settings.json"]
        options = (
            ["--check-onboarding"] if onboarding else (["--apply"] if apply else [])
        )
        monkeypatch.setattr(sys, "argv", arguments + options)
        return module.main()

    monkeypatch.setattr(module.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(module, "read_json", read)
    monkeypatch.setattr(module, "SystemdRouteHost", adapter)
    monkeypatch.setattr(module, "build_candidate", build)
    monkeypatch.setattr(module, "http_ready", health)
    monkeypatch.setattr(
        module, "validate_reader", lambda data, _: state.validations.append(data)
    )
    state.run = run
    return state


@pytest.mark.parametrize("ready", [True, False])
def test_onboarding_diagnostic_holds_lock_without_changing_viewer(
    cli, monkeypatch, capsys, ready
):
    cli.candidate = b'{"agent_actors": []}'
    monkeypatch.setattr(module, "parse_policy", lambda _: {"actors": []})

    def directories(unit):
        assert cli.host.locked and unit == "example-reader.service"
        return set()

    monkeypatch.setattr(module, "runtime_directories", directories)
    monkeypatch.setattr(module, "onboarding_report", lambda *_: {"ready": ready})
    assert cli.run(onboarding=True) == (0 if ready else 1)
    assert json.loads(capsys.readouterr().out) == {"ready": ready}
    assert cli.host.running and cli.host.stops == 0
    assert not cli.host.pending() and not cli.health_ports


def test_onboarding_probe_failure_preserves_running_viewer(cli, capsys):
    cli.baseline = PermissionError("private installation data")
    assert cli.run(onboarding=True) == 1
    assert cli.host.running and cli.host.stops == 0
    assert "private" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("private baseline path"),
        PermissionError("private baseline permissions"),
        ValueError("unsafe protected baseline"),
        json.JSONDecodeError("private baseline contents", "{", 1),
    ],
)
def test_apply_baseline_read_failure_stops_running_viewer(cli, capsys, error):
    cli.baseline = error
    assert cli.run() == 1
    assert not cli.host.running and cli.host.stops > 0
    assert cli.baseline_reads == [True]
    assert not cli.builds and not cli.health_ports
    assert cli.host.record is None and cli.host.committed == (b"old", "r1")
    assert json.loads(capsys.readouterr().out) == {"status": "reconciliation-refused"}


@pytest.mark.parametrize(
    "baseline",
    [
        None,
        [],
        {},
        {"port": None},
        {"port": True},
        {"port": "8789"},
        {"port": 80},
        {"port": 65536},
    ],
)
def test_apply_invalid_baseline_port_stops_before_build_or_health(cli, baseline):
    cli.baseline = baseline
    assert cli.run() == 1
    assert not cli.host.running and cli.host.stops > 0
    assert not cli.builds and not cli.health_ports
    assert cli.host.record is None


def test_unchanged_apply_uses_one_locked_baseline_for_build_and_health(cli, capsys):
    assert cli.run() == 0
    assert cli.host.running and cli.host.stops == 0
    assert cli.baseline_reads == [True]
    assert cli.builds[0][1] == {"port": 8789}
    assert cli.health_ports == [8789]
    assert json.loads(capsys.readouterr().out) == {"status": "unchanged"}


@pytest.mark.parametrize("pending", [False, True])
def test_corrected_baseline_recovers_stopped_viewer_on_next_apply(cli, capsys, pending):
    cli.candidate = b"freshly verified"
    if pending:
        cli.host.record = (cli.candidate, "r1")
    record = cli.host.record
    cli.baseline = PermissionError("private baseline permissions")
    assert cli.run() == 1 and not cli.host.running
    assert cli.host.record == record and cli.host.committed == (b"old", "r1")
    capsys.readouterr()
    cli.baseline = {"port": 8791}
    assert cli.run() == 0
    assert cli.host.running and cli.host.record is None
    assert cli.host.committed == (b"freshly verified", "r1")
    assert cli.health_ports == [8791]
    assert json.loads(capsys.readouterr().out) == {
        "status": "recovered" if pending else "updated"
    }


def test_read_only_baseline_failure_never_stops_running_viewer(cli, capsys):
    cli.baseline = FileNotFoundError("private baseline path")
    assert cli.run(apply=False) == 1
    assert cli.host.running and cli.host.stops == 0
    assert json.loads(capsys.readouterr().out) == {"status": "reconciliation-refused"}


def test_failed_emergency_stop_requires_manual_intervention(cli, capsys):
    cli.baseline = ValueError("private baseline contents")

    def cannot_stop():
        raise OSError("private systemctl details")

    cli.host.stop = cannot_stop
    assert cli.run() == 1
    assert cli.host.running and not cli.builds
    assert json.loads(capsys.readouterr().out) == {
        "status": "viewer-stop-failed",
        "manual_intervention_required": True,
    }
