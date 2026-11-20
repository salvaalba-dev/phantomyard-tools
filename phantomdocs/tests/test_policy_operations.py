"""Writer closure, isolated runtime and acknowledged-alert contracts."""

import hashlib
import json
from types import SimpleNamespace

import pytest

from phantomdocs import workflow_policy_alert as alert
from phantomdocs import workflow_policy_environment as environment
from phantomdocs import workflow_policy_operations as ops


@pytest.fixture
def configuration():
    return {
        "schema_version": 1,
        "source": "/srv/example/source",
        "destinations": ["/srv/example/bridge", "/srv/example/docs"],
        "policy_lock": "/etc/example/lock",
        "resolver": "/opt/example/resolver.js",
        "bridge_unit": "bridge.service",
        "organization": "sample-org",
        "python": "/opt/publisher/venv/bin/python",
        "runtime_seal": "/opt/publisher/seal.json",
        "runtime_seal_sha256": "a" * 64,
        "inventory": "/etc/example/writers.json",
        "inventory_sha256": "b" * 64,
    }


@pytest.fixture
def inventory(configuration):
    prefix = [
        configuration["python"],
        "-m",
        ops.MODULE,
        "--config",
        "/etc/example/config.json",
    ]
    return {
        "schema_version": 1,
        "owner": "Example operator",
        "expires_utc": "2099-01-01T00:00:00Z",
        "manual_source_writes": "prohibited",
        "external_writers_reviewed": True,
        "retired_units": ["old-refresh.timer", "old-refresh.service"],
        "writers": [
            {
                "role": role,
                "owner": "Example operator",
                "unit": role + ".service",
                "unit_sha256": "c" * 64,
                "command": prefix + [role]
                if role != "collect"
                else ["/opt/collector/bin/collect"],
            }
            for role in ("publish", "reconcile", "prestart", "collect")
        ],
    }


def test_inventory_requires_named_accountability_and_a_single_publisher_entry(
    configuration, inventory
):
    assert ops.validate_config(configuration) == configuration
    assert (
        ops.validate_inventory(inventory, configuration, "/etc/example/config.json")
        == inventory
    )


@pytest.mark.parametrize(
    "change",
    ["manual", "external", "expired", "bypass", "missing", "duplicate", "owner"],
)
def test_incomplete_writer_closure_is_not_a_ready_configuration(
    configuration, inventory, change
):
    if change == "manual":
        inventory["manual_source_writes"] = "allowed"
    elif change == "external":
        inventory["external_writers_reviewed"] = False
    elif change == "expired":
        inventory["expires_utc"] = "2000-01-01T00:00:00Z"
    elif change == "bypass":
        inventory["writers"][0]["command"] = [
            "/usr/bin/cp",
            "/candidate",
            configuration["source"],
        ]
    elif change == "missing":
        inventory["writers"].pop()
    elif change == "duplicate":
        inventory["writers"][1]["unit"] = inventory["writers"][0]["unit"]
    else:
        inventory["owner"] = ""
    with pytest.raises(ValueError):
        ops.validate_inventory(inventory, configuration, "/etc/example/config.json")


@pytest.mark.parametrize(
    "state,enabled,definition",
    [
        ("active", "disabled", "reviewed"),
        ("inactive", "enabled", "reviewed"),
        ("inactive", "static", "reviewed"),
        ("inactive", "disabled", "modified"),
    ],
)
def test_live_legacy_triggers_and_changed_unit_definitions_block_closure(
    configuration, inventory, monkeypatch, state, enabled, definition
):
    for writer in inventory["writers"]:
        writer["unit_sha256"] = hashlib.sha256(b"reviewed").hexdigest()

    def systemctl(*args):
        return 0, definition if args[0] == "cat" else state if args[
            0
        ] == "show" else enabled

    monkeypatch.setattr(ops, "_systemctl", systemctl)
    with pytest.raises(ValueError):
        ops.check_inventory(inventory, configuration, "/etc/example/config.json")


def test_audit_observes_units_without_stopping_or_disabling_them(
    configuration, inventory, monkeypatch
):
    calls = []
    for writer in inventory["writers"]:
        writer["unit_sha256"] = hashlib.sha256(b"reviewed").hexdigest()

    def systemctl(*args):
        calls.append(args)
        return (
            (0, "reviewed")
            if args[0] == "cat"
            else (0, "inactive")
            if args[0] == "show"
            else (1, "disabled")
        )

    monkeypatch.setattr(ops, "_systemctl", systemctl)
    ops.check_inventory(inventory, configuration, "/etc/example/config.json")
    assert {c[0] for c in calls} == {"cat", "show", "is-enabled"}


def test_artifacts_are_digest_pinned_not_accepted_by_filename(monkeypatch):
    monkeypatch.setattr(ops, "_read_protected", lambda _: b'{"ready":true}')
    with pytest.raises(ValueError, match="changed"):
        ops._artifact("/review", "a" * 64)


@pytest.mark.parametrize(
    "operation,review",
    [
        ("reconcile", {}),
        ("prestart", {}),
        ("bootstrap", {"bootstrap_source_sha256": "a" * 64}),
        (
            "publish",
            {
                "candidate": "/reviewed",
                "expected_source_sha256": "a" * 64,
                "candidate_sha256": "b" * 64,
            },
        ),
    ],
)
def test_every_entry_point_requires_receipt_binding_and_identical_ordered_fanout(
    configuration, monkeypatch, operation, review
):
    seen = []
    monkeypatch.setattr(
        ops.publisher, "refresh", lambda **kw: seen.append(kw) or "synchronized"
    )
    ops.execute(configuration, operation, **review)
    assert seen[0]["require_committed_source"] and seen[0]["commit_witness"]
    assert seen[0]["destination"] == configuration["destinations"]
    assert seen[0]["prestart"] == (operation == "prestart")
    assert all(seen[0][k] == v for k, v in review.items())


def test_reconcile_cannot_smuggle_a_candidate_or_bootstrap(configuration):
    with pytest.raises(ValueError):
        ops.execute(configuration, "reconcile", bootstrap_source_sha256="a" * 64)
    with pytest.raises(ValueError):
        ops.execute(configuration, "publish", candidate="/unreviewed")
    with pytest.raises(ValueError):
        ops.execute(configuration, "check", candidate="/unreviewed")


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("private detail"),
        ops.subprocess.TimeoutExpired("private command", 10),
    ],
)
def test_cli_sanitizes_failed_audit_and_unit_timeouts(monkeypatch, capsys, failure):
    monkeypatch.setattr(
        "sys.argv", ["policy-operations", "--config", "/example/config", "audit"]
    )

    def unavailable(_):
        raise failure

    monkeypatch.setattr(ops, "load_ready", unavailable)
    with pytest.raises(SystemExit) as stopped:
        ops.main()
    assert stopped.value.code == 2
    assert capsys.readouterr().out == "publisher operation unavailable\n"


def test_watchdog_fails_on_an_uncommitted_source_even_if_all_copies_match(
    configuration, monkeypatch
):
    seen = []
    monkeypatch.setattr(
        ops, "check", lambda **kw: seen.append(kw) or {"status": "drift"}
    )
    with pytest.raises(ValueError):
        ops.execute(configuration, "check")
    assert seen[0]["require_committed"] is True


def test_environment_seal_detects_modified_added_and_external_package_files(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(environment, "_protected_runtime", lambda: None)
    prefix = tmp_path / "venv"
    python = prefix / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"synthetic executable")
    for name in ("phantomdocs", "phantomorg"):
        directory = prefix / "lib" / name
        directory.mkdir(parents=True)
        (directory / "__init__.py").write_text("# reviewed")
    monkeypatch.setattr(environment.sys, "prefix", str(prefix))
    monkeypatch.setattr(environment.sys, "base_prefix", str(tmp_path))
    monkeypatch.setattr(environment.sys, "executable", str(python))
    monkeypatch.setattr(
        environment.importlib.util,
        "find_spec",
        lambda name: SimpleNamespace(origin=str(prefix / "lib" / name / "__init__.py")),
    )
    seal = environment.snapshot()
    environment.verify(seal, str(python))
    extra = prefix / "lib" / "phantomdocs" / "extra.py"
    extra.write_text("# unexpected")
    with pytest.raises(ValueError):
        environment.verify(seal, str(python))
    extra.unlink()
    (prefix / "lib" / "phantomdocs" / "__init__.py").write_text("# modified")
    with pytest.raises(ValueError):
        environment.verify(seal, str(python))
    monkeypatch.setattr(
        environment.importlib.util,
        "find_spec",
        lambda name: SimpleNamespace(origin=str(tmp_path / name / "__init__.py")),
    )
    with pytest.raises(ValueError, match="external"):
        environment.snapshot()


@pytest.mark.parametrize(
    "response,code",
    [
        ("{}", 0),
        ('{"delivered":false,"receipt":"x"}', 0),
        ('{"delivered":true,"receipt":""}', 0),
        ('{"delivered":true,"receipt":"x"}', 1),
        ("not-json", 0),
    ],
)
def test_logging_or_success_exit_alone_is_not_a_delivered_alert(
    monkeypatch, response, code
):
    monkeypatch.setattr(alert, "protected_handler", lambda _: None)
    monkeypatch.setattr(
        alert.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=code, stdout=response),
    )
    with pytest.raises(ValueError):
        alert.notify("/protected/handler", "example-refresh.service")


def test_alert_uses_bounded_shell_free_delivery_and_requires_a_receipt(monkeypatch):
    monkeypatch.setattr(alert, "protected_handler", lambda _: None)
    seen = []

    def run(*args, **kwargs):
        seen.append((args, kwargs))
        return SimpleNamespace(
            returncode=0, stdout='{"delivered":true,"receipt":"example:42"}'
        )

    monkeypatch.setattr(alert.subprocess, "run", run)
    assert (
        alert.notify("/protected/handler", "example-refresh.service", probe=True)
        == "example:42"
    )
    args, kw = seen[0]
    assert (
        args == (["/protected/handler"],) and kw["timeout"] == 20 and "shell" not in kw
    )
    assert json.loads(kw["input"]) == {
        "schema_version": 1,
        "kind": "policy-alert-probe",
        "unit": "example-refresh.service",
    }
    assert set(kw["env"]) == {"PATH", "LANG"}


@pytest.mark.parametrize(
    "unit", ["--help", "x.service\nExecStart=bad", "../x.service", "x;bad.service"]
)
def test_alert_rejects_unit_injection_before_executing_a_handler(unit):
    with pytest.raises(ValueError):
        alert.notify("/protected/handler", unit)


def test_alert_forwards_only_validated_persona_routing_not_process_secrets(monkeypatch):
    monkeypatch.setenv("PHANTOMBOT_PERSONA", "example-persona")
    monkeypatch.setenv("EXAMPLE_SECRET", "do-not-inherit")
    assert alert.delivery_environment() == {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PHANTOMBOT_PERSONA": "example-persona",
    }
    monkeypatch.setenv("PHANTOMBOT_PERSONA", "../other")
    with pytest.raises(ValueError):
        alert.delivery_environment()
