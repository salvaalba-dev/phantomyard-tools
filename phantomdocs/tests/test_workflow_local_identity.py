"""Linux-only protected UID mapping; no real identities or credentials."""

import json
import os
import socket
import struct
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from phantomdocs.workflow_local_identity import resolve_local_actor, resolve_peer_actor
from phantomdocs.workflows import WorkflowError


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires an isolated root-owned Linux test directory",
)
def test_protected_mapping_and_rejections(monkeypatch):
    with TemporaryDirectory(prefix="phantomdocs-identity-test-", dir="/root") as temp:
        path = Path(temp) / "identities.json"
        path.write_text(json.dumps({"version": 1, "actors": {"12345": "service"}}))
        path.chmod(0o644)
        monkeypatch.setattr(os, "geteuid", lambda: 12345)
        assert resolve_local_actor(path) == "service"

        monkeypatch.setattr(os, "geteuid", lambda: 12346)
        with pytest.raises(WorkflowError, match="not mapped"):
            resolve_local_actor(path)
        monkeypatch.setattr(os, "geteuid", lambda: 12345)
        path.chmod(0o664)
        with pytest.raises(WorkflowError, match="not protected"):
            resolve_local_actor(path)
        path.chmod(0o644)
        path.write_text('{"version":1,"actors":{"12345":"a","12345":"b"}}')
        with pytest.raises(WorkflowError, match="invalid local identity map"):
            resolve_local_actor(path)
        path.write_text(json.dumps({"version": 1, "actors": {"12345": "service"}}))
        symlink = Path(temp) / "link.json"
        symlink.symlink_to(path)
        with pytest.raises(OSError):
            resolve_local_actor(symlink)


def test_unsupported_platform_fails_closed(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(WorkflowError, match="Linux"):
        resolve_local_actor("/etc/phantomdocs/actors.json")


def test_peer_actor_uses_only_kernel_uid(monkeypatch):
    import phantomdocs.workflow_local_identity as identity

    monkeypatch.setattr(identity.sys, "platform", "linux")
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    observed = []
    monkeypatch.setattr(
        identity,
        "_resolve_actor_uid",
        lambda path, uid: observed.append((path, uid)) or "worker",
    )

    class Peer:
        family = socket.AF_UNIX
        type = socket.SOCK_STREAM

        def getsockopt(self, level, option, length):
            assert (level, option, length) == (
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
            return struct.pack("3i", 99, 12345, 100)

    assert resolve_peer_actor("/trusted/map", Peer()) == "worker"
    assert observed == [("/trusted/map", 12345)]


def test_peer_actor_rejects_wrong_transport_and_invalid_credentials(monkeypatch):
    import phantomdocs.workflow_local_identity as identity

    monkeypatch.setattr(identity.sys, "platform", "linux")
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)

    class Peer:
        family = socket.AF_INET
        type = socket.SOCK_STREAM

        def getsockopt(self, *args):
            return b"bad"

    with pytest.raises(WorkflowError, match="Unix stream"):
        resolve_peer_actor("/trusted/map", Peer())
    Peer.family = socket.AF_UNIX
    with pytest.raises(WorkflowError, match="credentials"):
        resolve_peer_actor("/trusted/map", Peer())


def test_peer_actor_rejects_root_uid(monkeypatch):
    import phantomdocs.workflow_local_identity as identity

    monkeypatch.setattr(identity.sys, "platform", "linux")
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)

    class Peer:
        family = socket.AF_UNIX
        type = socket.SOCK_STREAM

        def getsockopt(self, *args):
            return struct.pack("3i", 99, 0, 0)

    with pytest.raises(WorkflowError, match="root"):
        resolve_peer_actor("/trusted/map", Peer())


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux peer credentials")
def test_real_unix_socket_uses_actual_uid(monkeypatch):
    import phantomdocs.workflow_local_identity as identity

    observed = []
    monkeypatch.setattr(
        identity,
        "_resolve_actor_uid",
        lambda path, uid: observed.append(uid) or "worker",
    )
    first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert resolve_peer_actor("/trusted/map", first) == "worker"
        assert observed == [os.geteuid()]
    finally:
        first.close()
        second.close()
