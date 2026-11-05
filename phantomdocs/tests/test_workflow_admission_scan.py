"""Simulate scan-to-admission using the real protocol, planner and ledger.

The transport and peer identity are simulated; no Drive or document write occurs.
"""

import json
import os
import socket
import struct

import pytest
import test_workflow_scan as fixtures

from phantomdocs import workflow_admission_client as peer_client
from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_local_peer_protocol import serve_connection
from phantomdocs.workflow_scan import scan
from phantomdocs.workflows import plan


@pytest.fixture
def system():
    return fixtures.system.__wrapped__()


class ServerConnection:
    def __init__(self, data):
        self.data = data
        self.response = b""

    def settimeout(self, _timeout):
        pass

    def recv(self, size):
        result, self.data = self.data[:size], self.data[size:]
        return result

    def sendall(self, data):
        self.response += data


class SimulatedTransport:
    def __init__(self, ledger, org, planner):
        self.ledger, self.org, self.planner = ledger, org, planner
        self.data = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        pass

    def connect(self, _path):
        pass

    def getsockopt(self, *_args):
        return struct.pack("3i", 321, 123, 100)

    def sendall(self, payload):
        server = ServerConnection(payload)
        serve_connection(
            server,
            identity_map="/protected/identity-map",
            ledger=self.ledger,
            org=self.org,
            make_plan=self.planner,
        )
        self.data = server.response

    def recv(self, size):
        result, self.data = self.data[:size], self.data[size:]
        return result


def install_transport(monkeypatch, ledger, system, actor):
    org = system[2]
    planner = lambda job: plan(job, system[1], org, system[3], system[4], actor)
    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer.resolve_peer_actor", lambda *_: actor
    )
    monkeypatch.setattr(peer_client.sys, "platform", "linux")
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(
        peer_client.socket,
        "socket",
        lambda *_: SimulatedTransport(ledger, org, planner),
    )


def request(job):
    return peer_client.request_peer(os.path.abspath("peer.sock"), 123, {"job": job})


def test_scanned_job_admitted_once_without_processing(system, tmp_path, monkeypatch):
    result = scan(*system)
    row = result["items"][0]
    assert row["state"] == "planned" and row["requires_semantic_identity_check"]
    with WorkflowLedger(tmp_path / "ledger.sqlite") as ledger:
        install_transport(monkeypatch, ledger, system, "coordinator")
        assert request(row["job"]) == {"status": "received"}
        assert request(row["job"]) == {"status": "received"}
        assert ledger.connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
        assert (
            ledger.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        )
        stored = ledger.connection.execute(
            "SELECT state, request_json FROM jobs"
        ).fetchone()
        assert stored["state"] == "validated"
        assert json.loads(stored["request_json"])["job"] == row["job"]
        assert not ledger.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='workflow_archive_index'"
        ).fetchone()


def test_scanned_job_rejected_for_other_peer(system, tmp_path, monkeypatch):
    row = scan(*system)["items"][0]
    with WorkflowLedger(tmp_path / "ledger.sqlite") as ledger:
        install_transport(monkeypatch, ledger, system, "someone-else")
        assert request(row["job"]) == {"status": "rejected"}
        assert ledger.connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
