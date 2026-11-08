import json
import os
import struct
import sys
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


@pytest.mark.parametrize(
    "explicit, expected", [([], "agent-all"), (["--scope", "river"], "river")]
)
def test_cli_defaults_to_agent_scope_and_allows_explicit_selection(
    monkeypatch, capsys, explicit, expected
):
    config = {
        "schema_version": 1,
        "agent_uid": 100,
        "reader_uid": 200,
        "origin": "https://view.example",
        "socket_path": "/socket",
        "key_path": "/key",
    }
    monkeypatch.setattr(client, "os", SimpleNamespace(name="posix", getuid=lambda: 100))
    monkeypatch.setattr(
        client,
        "_read_fixed_file",
        lambda path, **_kwargs: (
            json.dumps(config).encode() if path == "/config" else b"key"
        ),
    )
    seen = {}
    monkeypatch.setattr(
        client,
        "request_agent_link",
        lambda **kwargs: seen.update(kwargs) or "https://view.example/#c=synthetic",
    )
    monkeypatch.setattr(
        sys, "argv", ["phantomview-link", "--config", "/config", *explicit]
    )
    client.main()
    assert seen["scope_id"] == expected
    assert capsys.readouterr().out.startswith("https://view.example/#c=")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file ownership required")
def test_untrusted_parent_cannot_hold_protected_configuration(tmp_path):
    target = tmp_path / "route.json"
    target.write_text("{}")
    tmp_path.chmod(0o777)
    with pytest.raises(ValueError, match="parent directory"):
        client._read_fixed_file(
            str(target), owner=os.getuid(), mode_mask=0o022, limit=4096
        )
