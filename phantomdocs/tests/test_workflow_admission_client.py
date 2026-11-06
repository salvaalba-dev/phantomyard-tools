"""Synthetic protocol tests; real Unix peer authentication requires Linux."""

import json
import os
import socket
import struct
import sys
import threading
from unittest import mock

import pytest

from phantomdocs import workflow_admission_client as peer_client


class Connection:
    def __init__(self, *, uid=123, response=b'{"status":"received"}\n'):
        self.uid = uid
        self.response = response
        self.sent = []
        self.connected = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, path):
        self.connected.append(path)

    def getsockopt(self, *_):
        return struct.pack("3i", 99, self.uid, 10)

    def sendall(self, value):
        self.sent.append(value)

    def recv(self, size):
        if isinstance(self.response, Exception):
            raise self.response
        part, self.response = self.response[:size], self.response[size:]
        return part


@pytest.fixture
def peer(monkeypatch):
    connection = Connection()
    monkeypatch.setattr(peer_client.sys, "platform", "linux")
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    factory = mock.Mock(return_value=connection)
    monkeypatch.setattr(peer_client.socket, "socket", factory)
    return connection, factory


def submit():
    return peer_client.request_peer(
        os.path.abspath("peer.sock"), 123, {"job": {"request_id": "sample"}}
    )


def test_checks_server_before_transmitting_job(peer):
    connection, factory = peer
    assert submit() == {"status": "received"}
    assert json.loads(connection.sent[0]) == {"job": {"request_id": "sample"}}
    assert factory.call_count == 1


def test_wrong_server_uid_never_receives_job(peer):
    connection, _ = peer
    connection.uid = 124
    with pytest.raises(peer_client.PeerClientError, match="untrusted"):
        submit()
    assert connection.sent == []


@pytest.mark.parametrize(
    "response",
    [
        b'{"status":"received","status":"indexed"}\n',
        b'{"status":"received","extra":true}\n',
        b'{"status":"unknown"}\n',
        b'{"status":"indexed"}\n',
        b"x" * 4098,
        b"",
    ],
)
def test_malformed_or_incomplete_response_is_not_a_success(peer, response):
    peer[0].response = response
    with pytest.raises(peer_client.PeerClientError):
        submit()
    assert len(peer[0].sent) == 1


def test_lost_response_does_not_retry(peer):
    connection, factory = peer
    connection.response = TimeoutError("synthetic")
    with pytest.raises(peer_client.PeerClientError, match="reconciliation"):
        submit()
    assert len(connection.sent) == 1
    assert factory.call_count == 1


def test_invalid_request_never_connects(peer):
    _, factory = peer
    with pytest.raises(peer_client.PeerClientError):
        peer_client.request_peer(
            os.path.abspath("peer.sock"), 123, {"job": {}, "actor": "another-actor"}
        )
    factory.assert_not_called()


def test_search_accepts_only_bounded_typed_results(peer):
    peer[0].response = (
        b'{"status":"ok","actor":"worker","items":'
        b'[{"kind":"doc","urn":"urn:example:doc:report"}]}\n'
    )
    result = peer_client.request_peer(
        os.path.abspath("peer.sock"), 123, {"search": {"query": "report"}}
    )
    assert result["actor"] == "worker"
    assert result["items"] == [{"kind": "doc", "urn": "urn:example:doc:report"}]


@pytest.mark.parametrize(
    "response",
    [
        b'{"status":"ok","actor":"worker","items":[],"extra":"hidden"}\n',
        b'{"status":"ok","actor":"worker","items":[{"kind":"doc","urn":"x","extra":1}]}\n',
        b'{"status":"ok","actor":"worker","items":[{"kind":"unknown","urn":"x"}]}\n',
        b'{"status":"ok","actor":"worker","items":null}\n',
    ],
)
def test_search_rejects_malformed_results(peer, response):
    peer[0].response = response
    with pytest.raises(peer_client.PeerClientError):
        peer_client.request_peer(
            os.path.abspath("peer.sock"), 123, {"search": {"query": "report"}}
        )


def test_lookup_accepts_authorized_reference_shape(peer):
    peer[0].response = (
        b'{"status":"ok","actor":"worker","result":'
        b'{"urn":"urn:example:doc:report","location":"gdrive://example"}}\n'
    )
    result = peer_client.request_peer(
        os.path.abspath("peer.sock"),
        123,
        {"lookup": {"operation": "reference", "ref": "report"}},
    )
    assert result["result"]["location"] == "gdrive://example"


def test_content_lookup_checks_reference_and_hash_shapes(peer):
    response = {
        "status": "ok",
        "actor": "worker",
        "result": {
            "urn": "urn:example:doc:report",
            "location": "gdrive://example",
            "contentHash": "a" * 64,
            "mac": "b" * 64,
        },
    }
    payload = {"lookup": {"operation": "content-reference", "ref": "report"}}
    peer[0].response = (json.dumps(response) + "\n").encode()
    assert (
        peer_client.request_peer(os.path.abspath("peer.sock"), 123, payload) == response
    )

    for key, bad in [("location", "gdrive://--bad"), ("contentHash", "x" * 64)]:
        damaged = {**response, "result": {**response["result"], key: bad}}
        peer[0].response = (json.dumps(damaged) + "\n").encode()
        with pytest.raises(peer_client.PeerClientError):
            peer_client.request_peer(os.path.abspath("peer.sock"), 123, payload)


@pytest.mark.parametrize(
    "operation,result",
    [
        (
            "status",
            {
                "org": "example",
                "namespace": "docs",
                "tenant": "single",
                "nodes": 1,
                "docs": 1,
                "folders": 0,
                "bytes": 4,
            },
        ),
        (
            "refs",
            [{"name": "latest", "mac": "a" * 64, "urn": "urn:example:doc:report"}],
        ),
    ],
)
def test_accepts_scoped_status_and_ref_results(peer, operation, result):
    response = {"status": "ok", "actor": "worker", "result": result}
    peer[0].response = (json.dumps(response) + "\n").encode()
    assert (
        peer_client.request_peer(
            os.path.abspath("peer.sock"), 123, {"lookup": {"operation": operation}}
        )
        == response
    )


def test_rejects_invalid_scoped_status_counts(peer):
    result = {
        "org": "example",
        "namespace": "docs",
        "tenant": "single",
        "nodes": 5,
        "docs": 1,
        "folders": 0,
        "bytes": 4,
    }
    peer[0].response = (
        json.dumps({"status": "ok", "actor": "worker", "result": result}) + "\n"
    ).encode()
    with pytest.raises(peer_client.PeerClientError):
        peer_client.request_peer(
            os.path.abspath("peer.sock"), 123, {"lookup": {"operation": "status"}}
        )


@pytest.mark.parametrize(
    "row",
    [
        {"mac": "x" * 64, "size": 4, "current": True},
        {"mac": "a" * 64, "size": -1, "current": True},
        {"mac": "a" * 64, "size": 4, "current": 1},
        {"mac": "a" * 64, "size": 4, "current": True, "extra": "hidden"},
    ],
)
def test_lookup_rejects_malformed_history(peer, row):
    peer[0].response = (
        json.dumps({"status": "ok", "actor": "worker", "result": [row]}) + "\n"
    ).encode()
    with pytest.raises(peer_client.PeerClientError):
        peer_client.request_peer(
            os.path.abspath("peer.sock"),
            123,
            {"lookup": {"operation": "versions", "ref": "report"}},
        )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SO_PEERCRED is required")
@pytest.mark.parametrize("trusted", [True, False])
def test_real_unix_peer_credentials(tmp_path, trusted):
    path = str(tmp_path / "peer.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)
    listener.settimeout(5)
    received = []

    def serve():
        with listener, listener.accept()[0] as conn:
            conn.settimeout(5)
            data = conn.recv(4096)
            received.append(data)
            if data:
                conn.sendall(b'{"status":"received"}\n')

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        expected_uid = os.getuid() if trusted else os.getuid() + 1
        if trusted:
            assert peer_client.request_peer(path, expected_uid, {"job": {}}) == {
                "status": "received"
            }
        else:
            with pytest.raises(peer_client.PeerClientError, match="untrusted"):
                peer_client.request_peer(path, expected_uid, {"job": {}})
    finally:
        thread.join(6)
    assert not thread.is_alive()
    assert bool(received[0]) is trusted
