"""Test the add-on CLI without starting a service or modifying any documents."""

import json

import pytest
import test_workflow_scan as fixtures
from click.testing import CliRunner

from phantomdocs import workflow_admission_submit as submit_workflow
from phantomdocs.cli import main
from phantomdocs.workflow_scan import scan


@pytest.fixture
def cli_case(tmp_path, monkeypatch):
    system = fixtures.system.__wrapped__()
    job = scan(*system)["items"][0]["job"]
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps(job), encoding="utf-8")
    config = {
        "store_path": str(tmp_path / "store"),
        "org_path": str(tmp_path / "org.yaml"),
        "socket_path": str(tmp_path / "socket"),
        "server_uid": 123,
    }
    calls = []
    monkeypatch.setattr(submit_workflow, "load_config", lambda _path: config)
    monkeypatch.setattr(
        submit_workflow,
        "request_peer",
        lambda *args: calls.append(args) or {"status": "received"},
    )
    args = [
        "--job",
        str(job_path),
        "--actor",
        "coordinator",
        "--root",
        config["store_path"],
        "--org-yaml",
        config["org_path"],
    ]
    return job, job_path, config, calls, args


def test_compatible_wrapper_arguments_submit_job_without_claiming_completion(cli_case):
    job, _, config, calls, args = cli_case
    result = CliRunner().invoke(main, ["submit-workflow", *args])
    assert result.exit_code == 0
    assert "has not been registered" in result.output
    assert calls == [(config["socket_path"], 123, {"job": job})]


def test_actor_mismatch_never_reaches_peer(cli_case):
    _, _, _, calls, args = cli_case
    args[args.index("--actor") + 1] = "different-actor"
    result = CliRunner().invoke(main, ["submit-workflow", *args])
    assert result.exit_code != 0
    assert calls == []


def test_other_store_never_reaches_peer(cli_case, tmp_path):
    _, _, _, calls, args = cli_case
    args[args.index("--root") + 1] = str(tmp_path / "other-store")
    result = CliRunner().invoke(main, ["submit-workflow", *args])
    assert result.exit_code != 0
    assert calls == []


def test_duplicate_json_fields_never_reach_peer(cli_case):
    _, job_path, _, calls, args = cli_case
    job_path.write_text('{"version":1,"version":1}', encoding="utf-8")
    result = CliRunner().invoke(main, ["submit-workflow", *args])
    assert result.exit_code != 0
    assert calls == []


def test_uncertain_outcome_never_retries(cli_case, monkeypatch):
    _, _, _, calls, args = cli_case

    def lose_response(*args):
        calls.append(args)
        raise submit_workflow.PeerClientError("synthetic timeout")

    monkeypatch.setattr(submit_workflow, "request_peer", lose_response)
    result = CliRunner().invoke(main, ["submit-workflow", *args])
    assert result.exit_code != 0
    assert "review the request before retrying" in result.output
    assert len(calls) == 1


@pytest.mark.parametrize("status,exit_code", [("blocked", 2), ("rejected", 1)])
def test_blocked_and_rejected_requests_are_not_reported_as_success(
    cli_case, monkeypatch, status, exit_code
):
    _, _, _, _, args = cli_case
    monkeypatch.setattr(submit_workflow, "request_peer", lambda *_: {"status": status})
    result = CliRunner().invoke(main, ["submit-workflow", *args])
    assert result.exit_code == exit_code
    assert "Request received for review" not in result.output
