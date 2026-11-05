"""Requester processing is opt-in and requires a bound authenticated actor."""

import json
from copy import deepcopy
from datetime import timedelta

import coincurve
import pytest
import test_workflow_scan as fixtures
import yaml
from click.testing import CliRunner
from test_workflow_executor import FakeDrive

from phantomdocs.cli import main
from phantomdocs.signing import npub_encode, pubkey_from_nsec
from phantomdocs.workflow_executor import WorkflowExecutor
from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_requests import sign_request, utc_now, utc_text
from phantomdocs.workflow_scan import scan
from phantomdocs.workflows import WorkflowError, plan, resolve_installation_processor


@pytest.fixture
def system():
    values = fixtures.system.__wrapped__()
    values[1]["processor"]["source"] = "authenticated-requester"
    return values


def test_planner_uses_the_requester_without_phantombot_config(system):
    assert resolve_installation_processor(system[1], None) is None
    row = scan(*system[:4], None, *system[5:])["items"][0]
    assert row["plan"]["processor"] == {
        "actor": "coordinator",
        "source": "authenticated-requester",
    }
    rebuilt = plan(row["job"], system[1], system[2], system[3], None, "coordinator")
    assert rebuilt["plan_hash"] == row["plan"]["plan_hash"]


def test_other_caller_cannot_select_requester_as_processor(system):
    row = scan(*system[:4], None, *system[5:])["items"][0]
    job = deepcopy(row["job"])
    job["requester"] = "remote-lead"
    with pytest.raises(WorkflowError, match="authenticated requester"):
        plan(job, system[1], system[2], system[3], None, "coordinator")


def test_requester_mode_never_overrides_phantomorg_denial(system):
    system[2]["policies"]["access_levels"]["internal"]["categories"] = []
    with pytest.raises(WorkflowError):
        scan(*system[:4], None, *system[5:])


def test_default_processor_still_requires_phantombot_config(system):
    system[1]["processor"]["source"] = "phantombot-default"
    with pytest.raises(WorkflowError, match="configuration is required"):
        resolve_installation_processor(system[1], None)


def test_local_job_executes_only_with_the_same_authorized_requester(system, tmp_path):
    row = scan(*system[:4], None, *system[5:])["items"][0]
    job = row["job"]
    build = lambda value: plan(
        value, system[1], system[2], system[3], None, "coordinator"
    )
    with WorkflowLedger(tmp_path / "ledger.sqlite") as ledger:
        ledger.accept_local(job, system[2], "coordinator", build)
        backend = FakeDrive()
        executor = WorkflowExecutor(ledger, ledger.path, backend)
        result = executor.run(
            "example-org", job["request_id"], system[2], "coordinator", build
        )
        assert result["state"] == "indexed"
        assert backend.calls == ["$inputs", "index"]
        with pytest.raises(WorkflowError):
            executor.run(
                "example-org", job["request_id"], system[2], "remote-lead", build
            )
        assert backend.calls == ["$inputs", "index"]


def test_signed_remote_job_cannot_use_local_requester_mode(system, tmp_path):
    secret = coincurve.PrivateKey().secret.hex()
    system[2]["actors"][0]["npub"] = npub_encode(pubkey_from_nsec(secret))
    job = scan(*system[:4], None, *system[5:])["items"][0]["job"]
    signed = sign_request(
        job, system[2], secret, utc_text(utc_now() + timedelta(hours=1))
    )
    build = lambda value: plan(
        value, system[1], system[2], system[3], None, "coordinator"
    )
    with WorkflowLedger(tmp_path / "ledger.sqlite") as ledger:
        with pytest.raises(WorkflowError, match="requires authenticated local intake"):
            ledger.accept(signed, system[2], "coordinator", build)
        assert ledger.connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0


def test_scan_cli_needs_no_phantombot_config_in_requester_mode(
    system, tmp_path, monkeypatch
):
    from phantomdocs import cli

    monkeypatch.setattr(cli, "_require_acl", lambda *_: ("coordinator", system[2]))
    (tmp_path / "inventory.json").write_text(json.dumps(system[0]), encoding="utf-8")
    (tmp_path / "installation.json").write_text(json.dumps(system[1]), encoding="utf-8")
    (tmp_path / "manifest.yaml").write_text(yaml.safe_dump(system[6]), encoding="utf-8")
    (tmp_path / "org.yaml").write_text(yaml.safe_dump(system[2]), encoding="utf-8")
    result = CliRunner().invoke(
        main,
        [
            "workflow",
            "scan",
            "--inventory",
            str(tmp_path / "inventory.json"),
            "--installation",
            str(tmp_path / "installation.json"),
            "--org-yaml",
            str(tmp_path / "org.yaml"),
            "--root",
            str(tmp_path),
            "--domain",
            "projects",
            "--document-type",
            "report",
            "--requesting-domain",
            "projects",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["items"][0]["plan"]["processor"] == {
        "actor": "coordinator",
        "source": "authenticated-requester",
    }
