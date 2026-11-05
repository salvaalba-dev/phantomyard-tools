"""Synthetic host wiring tests with the real planner, protocol and ledger."""

import json
import os
from copy import deepcopy

import pytest
import test_workflow_scan as fixtures
from test_workflow_admission_scan import ServerConnection

from phantomdocs import workflow_admission_host as admission_host
from phantomdocs import workflow_admission_service as configured_admission
from phantomdocs.workflow_local_peer_protocol import serve_connection
from phantomdocs.workflow_scan import scan


@pytest.fixture
def system():
    return fixtures.system.__wrapped__()


def run_host(monkeypatch, system, tmp_path, request, *, actor="coordinator"):
    seen = []

    def controlled_serve(listener, context_factory, *, policy_lock, load_org):
        seen.append((listener, policy_lock))
        with context_factory(load_org()) as context:
            connection = ServerConnection((json.dumps(request) + "\n").encode())
            serve_connection(connection, **context)
            return json.loads(connection.response)

    monkeypatch.setattr(admission_host, "serve_one", controlled_serve)
    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer.resolve_peer_actor", lambda *_: actor
    )
    result = admission_host.serve_admission_once(
        "supervised-listener",
        identity_map="/protected/map",
        ledger_path=tmp_path / "ledger.sqlite",
        policy_lock="/protected/policy.lock",
        load_org=lambda: deepcopy(system[2]),
        load_installation=lambda: deepcopy(system[1]),
        processor=system[4],
    )
    assert seen == [("supervised-listener", "/protected/policy.lock")]
    return result


def test_host_admits_scanned_job_and_repeats_without_duplicate(
    system, tmp_path, monkeypatch
):
    job = scan(*system)["items"][0]["job"]
    assert run_host(monkeypatch, system, tmp_path, {"job": job}) == {
        "status": "received"
    }
    assert run_host(monkeypatch, system, tmp_path, {"job": job}) == {
        "status": "received"
    }
    from phantomdocs.workflow_ledger import WorkflowLedger

    with WorkflowLedger(tmp_path / "ledger.sqlite") as ledger:
        assert ledger.connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
        assert (
            ledger.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        )


def test_host_rejects_other_actor_and_archive_requests(system, tmp_path, monkeypatch):
    job = scan(*system)["items"][0]["job"]
    assert run_host(
        monkeypatch, system, tmp_path, {"job": job}, actor="different-actor"
    ) == {"status": "rejected"}
    assert run_host(monkeypatch, system, tmp_path, {"archive": "sample"}) == {
        "status": "rejected"
    }


def test_host_rejects_invalid_trusted_installation(system, tmp_path, monkeypatch):
    system[1].clear()
    with pytest.raises(ValueError):
        run_host(monkeypatch, system, tmp_path, {"job": {}})
    assert not (tmp_path / "ledger.sqlite").exists()


def test_configured_host_passes_only_protected_settings(system, tmp_path, monkeypatch):
    job = scan(*system)["items"][0]["job"]
    server_uid = os.geteuid() if hasattr(os, "geteuid") else 123
    config = {
        "identity_map": "/protected/map",
        "ledger_path": str(tmp_path / "ledger.sqlite"),
        "policy_lock": "/protected/policy.lock",
        "org_path": "/protected/org.yaml",
        "installation_path": "/protected/installation.json",
        "processor_config_path": "/protected/bot.toml",
        "processor_state_path": None,
        "server_uid": server_uid,
    }
    monkeypatch.setattr(configured_admission, "load_config", lambda _path: config)
    monkeypatch.setattr(
        configured_admission.os, "geteuid", lambda: server_uid, raising=False
    )
    monkeypatch.setattr(configured_admission, "load_policy", lambda _path: system[2])
    monkeypatch.setattr(
        configured_admission, "load_processor", lambda _config, _state: system[4]
    )
    monkeypatch.setattr(
        configured_admission, "load_installation", lambda _path: system[1]
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer.resolve_peer_actor", lambda *_: "coordinator"
    )

    def controlled_serve(_listener, context_factory, *, policy_lock, load_org):
        assert policy_lock == config["policy_lock"]
        with context_factory(load_org()) as context:
            connection = ServerConnection((json.dumps({"job": job}) + "\n").encode())
            serve_connection(connection, **context)
            return json.loads(connection.response)

    monkeypatch.setattr(admission_host, "serve_one", controlled_serve)
    assert configured_admission.serve_configured_once(
        "listener", "/protected/host.json"
    ) == {"status": "received"}
    from phantomdocs.workflow_ledger import WorkflowLedger
    from phantomdocs.workflows import load_registry, plan

    rebuilt = plan(
        job, system[1], system[2], load_registry(), system[4], job["requester"]
    )
    with WorkflowLedger(tmp_path / "ledger.sqlite", readonly=True) as ledger:
        row = ledger.connection.execute("SELECT plan_hash FROM jobs").fetchone()
        assert row["plan_hash"] == rebuilt["plan_hash"]


def test_configured_host_refuses_a_different_service_account(monkeypatch):
    monkeypatch.setattr(
        configured_admission, "load_config", lambda _path: {"server_uid": 123}
    )
    monkeypatch.setattr(configured_admission.os, "geteuid", lambda: 124, raising=False)
    with pytest.raises(ValueError, match="service account"):
        configured_admission.serve_configured_once("listener", "/protected/host.json")
