import json
import socket
import struct
from contextlib import contextmanager

from phantomdocs.workflow_audit_peer import REQUEST, serve_connection


class Connection:
    family = getattr(socket, "AF_UNIX", 1)
    type = socket.SOCK_STREAM

    def __init__(self, uid, request=REQUEST):
        self.uid, self.request, self.output, self.closed = uid, request, b"", False

    def settimeout(self, seconds):
        self.timeout = seconds

    def getsockopt(self, *args):
        return struct.pack("3i", 123, self.uid, 123)

    def recv(self, count):
        part, self.request = self.request[:count], self.request[count:]
        return part

    def sendall(self, data):
        self.output += data

    def close(self):
        self.closed = True


def test_peer_delivers_only_under_guard_and_rejects_other_uid(monkeypatch):
    monkeypatch.setattr(socket, "AF_UNIX", getattr(socket, "AF_UNIX", 1), raising=False)
    monkeypatch.setattr(
        socket, "SO_PEERCRED", getattr(socket, "SO_PEERCRED", 17), raising=False
    )
    module = "phantomdocs.workflow_audit_peer."
    config = {
        "version": 1,
        "owner_uid": 1001,
        "authority_config": "/authority",
        "evidence_path": "/evidence",
    }
    monkeypatch.setattr(module + "_json", lambda path: config)
    state = {"held": False}

    @contextmanager
    def guard(path, peer):
        state["held"] = True
        try:
            yield lambda evidence: None
        finally:
            state["held"] = False

    def read(path, owner_uid):
        assert state["held"] and owner_uid == 1001
        return {"matrix_text": "review"}

    monkeypatch.setattr(module + "guarded_peer_authorizer", guard)
    monkeypatch.setattr(module + "read_evidence", read)
    good = Connection(1001)
    serve_connection(good, "/config")
    assert json.loads(good.output)["evidence"]["matrix_text"] == "review"
    assert good.closed and not state["held"]
    bad = Connection(1002)
    serve_connection(bad, "/config")
    assert json.loads(bad.output) == {"error": "review unavailable"}
    assert bad.closed
