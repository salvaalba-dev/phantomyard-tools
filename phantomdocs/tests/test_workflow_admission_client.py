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
