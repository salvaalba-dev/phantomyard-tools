"""The peer protocol must bound input and avoid leaking internal details."""

import json

import pytest

from phantomdocs.workflow_local_peer_protocol import MAX_REQUEST_BYTES, serve_connection


class Connection:
    def __init__(self, data):
        self.data = data
        self.response = b""

    def settimeout(self, value):
        assert value == 5

    def recv(self, size):
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk

    def sendall(self, data):
        self.response += data


def call(connection):
    serve_connection(
        connection,
        identity_map="/protected/map",
        ledger=object(),
        org={},
        make_plan=lambda _: None,
    )
    return json.loads(connection.response)


def test_admits_job_and_reports_blocked(monkeypatch):
    seen = []

    def accept(connection, mapping, job, **kwargs):
        seen.append((connection, mapping, job))
        return {"state": "blocked", "private_document": "must not leak"}

    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_protocol.accept_peer_job", accept
    )
    connection = Connection(b'{"job":{"request_id":"r1"}}\n')
    assert call(connection) == {"status": "blocked"}
    assert seen == [(connection, "/protected/map", {"request_id": "r1"})]


@pytest.mark.parametrize(
    "data",
    [
        b'{"job":{},"job":{}}\n',
        b'{"job":{}}',
        b'{"job":{},"actor":"x"}\n',
        b'{"job":NaN}\n',
        b'{"job":{}}\nextra',
        pytest.param(b"x" * (MAX_REQUEST_BYTES + 2), id="oversized"),
    ],
)
def test_invalid_input_never_reaches_admission(data, monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("invalid request reached admission")

    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_protocol.accept_peer_job", fail
    )
    assert call(Connection(data)) == {"status": "rejected"}


def test_errors_return_generic_response(monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("private diagnostic")

    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_protocol.accept_peer_job", fail
    )
    assert call(Connection(b'{"job":{}}\n')) == {"status": "rejected"}


def test_archive_uses_only_host_context(monkeypatch):
    seen = []
    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_protocol.index_peer_archive",
        lambda *args, **kwargs: seen.append((args, kwargs)),
    )
    connection = Connection(b'{"archive":"r1"}\n')
    ledger, org = object(), {}
    serve_connection(
        connection,
        identity_map="/protected/map",
        ledger=ledger,
        org=org,
        make_plan=lambda _: None,
        archive_context={"receipt_directory": "/protected/receipts"},
    )
    assert json.loads(connection.response) == {"status": "indexed"}
    assert seen == [
        (
            (connection, "r1"),
            {
                "identity_map": "/protected/map",
                "ledger": ledger,
                "org": org,
                "receipt_directory": "/protected/receipts",
            },
        )
    ]


@pytest.mark.parametrize(
    "data",
    [
        b'{"archive":"r1"}\n',
        b'{"archive":"r1","actor":"other"}\n',
        b'{"archive":"r1","job":{}}\n',
    ],
)
def test_archive_requires_host_configuration_and_exact_request(data, monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("unauthorized archive request reached indexing")

    monkeypatch.setattr(
        "phantomdocs.workflow_local_peer_protocol.index_peer_archive", fail
    )
    assert call(Connection(data)) == {"status": "rejected"}
