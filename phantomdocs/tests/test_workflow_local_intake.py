"""Trusted local intake never authenticates a remote sender."""

import json
from copy import deepcopy
from datetime import timedelta

import coincurve
import pytest
import test_workflows as fixtures
import yaml
from click.testing import CliRunner
from test_workflow_executor import FakeDrive

from phantomdocs.cli import main
from phantomdocs.signing import npub_encode, pubkey_from_nsec
from phantomdocs.workflow_cli import _require_local_job_actor
from phantomdocs.workflow_executor import WorkflowExecutor
from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_requests import sign_request, utc_now, utc_text
from phantomdocs.workflows import WorkflowError


def context(tmp_path):
    org = fixtures.model.__wrapped__()
    installation = fixtures.installation.__wrapped__()
    job = fixtures.job.__wrapped__()
    job["requester"] = "coordinator"

    def build(value):
        return fixtures.make_plan(value, installation, org)

    return org, job, build, tmp_path / "ledger.sqlite"


def test_local_admission_executes_once_and_preserves_history(tmp_path):
    org, job, build, path = context(tmp_path)
    with WorkflowLedger(path) as ledger:
        first = ledger.accept_local(job, org, "coordinator", build)
        assert len(first["events"]) == 1
        assert first["events"][0]["event"] == "accepted-local"
        repeated = ledger.accept_local(job, org, "coordinator", build)
        assert repeated["unchanged"] and len(repeated["events"]) == 1
        backend = FakeDrive()
        executor = WorkflowExecutor(ledger, path, backend)
        result = executor.run("example-org", "request-001", org, "coordinator", build)
        assert result["state"] == "indexed"
        executor.run("example-org", "request-001", org, "coordinator", build)
        assert backend.calls == ["$inputs", "index"]


@pytest.mark.parametrize("operation", ["$inputs", "index"])
def test_local_execution_reconciles_after_backend_commit(tmp_path, operation):
    org, job, build, path = context(tmp_path)
    backend = FakeDrive()
    backend.fail_after = operation
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        executor = WorkflowExecutor(ledger, path, backend)
        with pytest.raises(RuntimeError):
            executor.run("example-org", "request-001", org, "coordinator", build)
        backend.fail_after = None
        result = executor.run("example-org", "request-001", org, "coordinator", build)
        assert result["state"] == "indexed"
        assert backend.calls.count(operation) == 1


def test_local_recovery_stops_without_a_backend_receipt(tmp_path):
    org, job, build, path = context(tmp_path)
    backend = FakeDrive()
    backend.fail_after = "$inputs"
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        executor = WorkflowExecutor(ledger, path, backend)
        with pytest.raises(RuntimeError):
            executor.run("example-org", "request-001", org, "coordinator", build)
        backend.fail_after = None
        backend.receipts.clear()
        with pytest.raises(WorkflowError, match="requires review"):
            executor.run("example-org", "request-001", org, "coordinator", build)
        assert backend.calls == ["$inputs"]


def test_local_recovery_stops_when_permissions_change(tmp_path):
    org, job, build, path = context(tmp_path)
    backend = FakeDrive()
    backend.fail_after = "$inputs"
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        executor = WorkflowExecutor(ledger, path, backend)
        with pytest.raises(RuntimeError):
            executor.run("example-org", "request-001", org, "coordinator", build)
        backend.fail_after = None
        org["policies"]["access_levels"]["internal"]["categories"] = []
        with pytest.raises(WorkflowError):
            executor.run("example-org", "request-001", org, "coordinator", build)
        assert backend.calls == ["$inputs"]


def test_local_intent_cannot_claim_a_different_requester(tmp_path):
    org, job, build, path = context(tmp_path)
    job["requester"] = "remote-lead"
    with WorkflowLedger(path) as ledger:
        with pytest.raises(WorkflowError, match="trusted local caller"):
            ledger.accept_local(job, org, "coordinator", build)
        assert ledger.connection.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0


def test_local_retry_rechecks_current_write_access(tmp_path):
    org, job, build, path = context(tmp_path)
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        org["policies"]["access_levels"]["internal"]["categories"] = []
        with pytest.raises(WorkflowError):
            ledger.accept_local(job, org, "coordinator", build)


def test_local_request_id_cannot_change_intent(tmp_path):
    org, job, build, path = context(tmp_path)
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        changed = deepcopy(job)
        changed["artifacts"][0]["ref"] = "gdrive://different"
        with pytest.raises(WorkflowError, match="different intent"):
            ledger.accept_local(changed, org, "coordinator", build)


def test_local_execution_rejects_revoked_requester_access(tmp_path):
    org, job, build, path = context(tmp_path)
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        org["policies"]["access_levels"]["internal"]["categories"] = []
        backend = FakeDrive()
        with pytest.raises(WorkflowError):
            WorkflowExecutor(ledger, path, backend).run(
                "example-org", "request-001", org, "coordinator", build
            )
        assert backend.calls == []


def test_local_retry_does_not_convert_signed_request(tmp_path):
    org, job, build, path = context(tmp_path)
    secret = coincurve.PrivateKey().secret.hex()
    org["actors"][0]["npub"] = npub_encode(pubkey_from_nsec(secret))
    signed = sign_request(job, org, secret, utc_text(utc_now() + timedelta(hours=1)))
    with WorkflowLedger(path) as ledger:
        ledger.accept(signed, org, "coordinator", build)
        with pytest.raises(WorkflowError, match="different trust mode"):
            ledger.accept_local(job, org, "coordinator", build)


def test_signed_retry_does_not_convert_local_request(tmp_path):
    org, job, build, path = context(tmp_path)
    secret = coincurve.PrivateKey().secret.hex()
    org["actors"][0]["npub"] = npub_encode(pubkey_from_nsec(secret))
    signed = sign_request(job, org, secret, utc_text(utc_now() + timedelta(hours=1)))
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        with pytest.raises(WorkflowError, match="different trust mode"):
            ledger.accept(signed, org, "coordinator", build)


def test_modified_local_intent_is_rejected_before_execution(tmp_path):
    org, job, build, path = context(tmp_path)
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        row = ledger._find("example-org", "request-001")
        envelope = json.loads(row["request_json"])
        envelope["job"]["artifacts"][0]["ref"] = "gdrive://different"
        ledger.connection.execute(
            "UPDATE jobs SET request_json=? WHERE organization=? AND request_id=?",
            (json.dumps(envelope), "example-org", "request-001"),
        )
        backend = FakeDrive()
        with pytest.raises(WorkflowError, match="does not match ledger"):
            WorkflowExecutor(ledger, path, backend).run(
                "example-org", "request-001", org, "coordinator", build
            )
        assert backend.calls == []


def test_cli_uses_mapped_actor_and_never_a_user_supplied_actor(tmp_path, monkeypatch):
    from phantomdocs import workflow_local_identity

    org, job, _, path = context(tmp_path)
    installation = fixtures.installation.__wrapped__()
    org_path = tmp_path / "org.yaml"
    org_path.write_text(yaml.safe_dump(org))
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps(job))
    installation_path = tmp_path / "installation.json"
    installation_path.write_text(json.dumps(installation))
    config_path = tmp_path / "bot.toml"
    config_path.write_text('default_persona = "coordinator"')
    map_path = tmp_path / "identity.json"
    map_path.write_text("{}")
    monkeypatch.setattr(
        workflow_local_identity, "resolve_local_actor", lambda _: "coordinator"
    )
    args = [
        "workflow",
        "accept-local",
        "--job",
        str(job_path),
        "--identity-map",
        str(map_path),
        "--ledger",
        str(path),
        "--installation",
        str(installation_path),
        "--org-yaml",
        str(org_path),
        "--phantombot-config",
        str(config_path),
    ]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["requester"] == "coordinator"
    result = CliRunner().invoke(main, args + ["--actor", "remote-lead"])
    assert result.exit_code != 0


def test_later_local_mutations_require_the_mapped_account(tmp_path, monkeypatch):
    from phantomdocs import workflow_local_identity

    org, job, build, path = context(tmp_path)
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
        with pytest.raises(WorkflowError, match="does not match"):
            _require_local_job_actor(
                ledger, "example-org", "request-001", "coordinator", None
            )
        monkeypatch.setattr(
            workflow_local_identity, "resolve_local_actor", lambda _: "other"
        )
        with pytest.raises(WorkflowError, match="does not match"):
            _require_local_job_actor(
                ledger, "example-org", "request-001", "coordinator", "map"
            )
        monkeypatch.setattr(
            workflow_local_identity, "resolve_local_actor", lambda _: "coordinator"
        )
        _require_local_job_actor(
            ledger, "example-org", "request-001", "coordinator", "map"
        )


def test_prepare_cli_rejects_mismatched_local_identity_before_processing(
    tmp_path, monkeypatch
):
    from phantomdocs import workflow_local_identity

    org, job, build, path = context(tmp_path)
    with WorkflowLedger(path) as ledger:
        ledger.accept_local(job, org, "coordinator", build)
    org_path = tmp_path / "org.yaml"
    org_path.write_text(yaml.safe_dump(org))
    install_path = tmp_path / "installation.json"
    install_path.write_text(json.dumps(fixtures.installation.__wrapped__()))
    config_path = tmp_path / "bot.toml"
    config_path.write_text('default_persona = "coordinator"')
    map_path = tmp_path / "identity.json"
    map_path.write_text("{}")
    token_path = tmp_path / "token"
    token_path.write_text("synthetic-token")
    monkeypatch.setattr(
        workflow_local_identity, "resolve_local_actor", lambda _: "other"
    )
    result = CliRunner().invoke(
        main,
        [
            "workflow",
            "prepare",
            "--request-id",
            "request-001",
            "--ledger",
            str(path),
            "--installation",
            str(install_path),
            "--org-yaml",
            str(org_path),
            "--actor",
            "coordinator",
            "--phantombot-config",
            str(config_path),
            "--drive-token-file",
            str(token_path),
            "--identity-map",
            str(map_path),
        ],
    )
    assert result.exit_code != 0
    assert "does not match local account" in result.output
