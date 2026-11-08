import json
import struct
from types import SimpleNamespace

import pytest

from phantomdocs import view_agent_link as client


class FakeSocket:
    def __init__(self, uid):
        self.uid = uid
        payload = json.dumps(
            {"schema_version": 1, "link": "https://view.example/#c=" + "a" * 43}
        ).encode()
        self.reply = struct.pack("!I", len(payload)) + payload
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def settimeout(self, _value):
        pass

    def connect(self, _path):
        pass

    def getsockopt(self, *_args):
        return struct.pack("3i", 1, self.uid, 1)

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        result, self.reply = self.reply[:size], self.reply[size:]
        return result


def configure(monkeypatch, uid):
    fake = FakeSocket(uid)
    monkeypatch.setattr(
        client,
        "socket",
        SimpleNamespace(
            AF_UNIX=1,
            SOCK_STREAM=1,
            SOL_SOCKET=1,
            SO_PEERCRED=1,
            socket=lambda *_args: fake,
        ),
    )
    monkeypatch.setattr(client, "sign_viewer_request", lambda *_args: "Nostr synthetic")
    monkeypatch.setattr(
        client,
        "Path",
        lambda _path: SimpleNamespace(
            is_absolute=lambda: True,
            parts=("/", "socket"),
            is_symlink=lambda: False,
            parents=[],
        ),
    )
    return fake


def test_link_request_uses_fixed_scope_after_checking_reader(monkeypatch):
    fake = configure(monkeypatch, 200)
    link = client.request_agent_link(
        secret=b"synthetic",
        origin="https://view.example",
        scope_id="river",
        socket_path="/socket",
        reader_uid=200,
    )
    assert link.endswith("a" * 43)
    assert json.loads(fake.sent[4:])["scope_id"] == "river"


def test_unknown_reader_receives_no_request(monkeypatch):
    fake = configure(monkeypatch, 201)
    with pytest.raises(ValueError, match="Unexpected"):
        client.request_agent_link(
            secret=b"synthetic",
            origin="https://view.example",
            scope_id="river",
            socket_path="/socket",
            reader_uid=200,
        )
    assert not fake.sent
