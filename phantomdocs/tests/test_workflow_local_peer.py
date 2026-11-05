"""Peer admission must use the authenticated actor and native authorization."""

from copy import deepcopy

import pytest
from test_workflow_local_intake import context

from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_local_peer import accept_peer_job
from phantomdocs.workflows import WorkflowError


def test_peer_admission_uses_native_ledger_and_is_idempotent(tmp_path, monkeypatch):
    org, job, build, path = context(tmp_path)
    peer = object()
    seen = []
    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer.resolve_peer_actor",
        lambda mapping, connection: seen.append((mapping, connection)) or "coordinator",
    )
    with WorkflowLedger(path) as ledger:
        first = accept_peer_job(
            peer, "/protected/map", job, ledger=ledger, org=org, make_plan=build
        )
        second = accept_peer_job(
            peer, "/protected/map", job, ledger=ledger, org=org, make_plan=build
        )
    assert first["events"][0]["event"] == "accepted-local"
    assert second["unchanged"] and len(second["events"]) == 1
    assert seen == [("/protected/map", peer), ("/protected/map", peer)]


def test_peer_cannot_impersonate_another_requester(tmp_path, monkeypatch):
    org, job, build, path = context(tmp_path)
    job = deepcopy(job)
    job["requester"] = "remote-lead"
    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer.resolve_peer_actor",
        lambda *_: "coordinator",
    )
    with WorkflowLedger(path) as ledger:
        with pytest.raises(WorkflowError, match="trusted local caller"):
            accept_peer_job(
                object(), "/protected/map", job, ledger=ledger, org=org, make_plan=build
            )
        assert ledger.connection.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0


def test_peer_failure_never_admits_job(tmp_path, monkeypatch):
    org, job, build, path = context(tmp_path)

    def reject(*_):
        raise WorkflowError("unmapped peer")

    monkeypatch.setattr("phantomdocs.workflow_local_peer.resolve_peer_actor", reject)
    with WorkflowLedger(path) as ledger:
        with pytest.raises(WorkflowError, match="unmapped peer"):
            accept_peer_job(
                object(), "/protected/map", job, ledger=ledger, org=org, make_plan=build
            )
        assert ledger.connection.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0
