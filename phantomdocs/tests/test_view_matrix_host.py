import os
import subprocess
import sys
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from phantomdocs import view_matrix_broker as broker
from phantomdocs import view_matrix_host as host


def test_host_runs_workspace_worker_under_fixed_actor_identity(monkeypatch):
    config = {
        "version": 1,
        "actor": "agent",
        "client_uid": 1001,
        "agent_uid": 1002,
        "agent_gid": 1003,
        "agent_home": "/home/agent",
        "workspace": "/agent/workspace",
        "python": "/usr/bin/python3",
        "pythonpath": "/opt/code",
        "policy_lock": "/etc/lock",
        "org_path": "/etc/org",
        "native_manifest": "/var/store/manifest",
        "binding": {
            "versions": {},
            "root_ref": "gdrive://rootfolder1",
            "domain": "dept",
            "project_type": "project",
        },
    }
    monkeypatch.setattr(host, "_json", lambda path: config)
    assert host.load_config("/trusted/config") == config
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout=b"matrix")

    @contextmanager
    def authority(**kwargs):
        yield {}, {}, kwargs["reader"]

    def serve(connection, **kwargs):
        assert kwargs["actor"] == "agent" and kwargs["client_uid"] == 1001
        with kwargs["authority"]("agent") as (_, _, reader):
            assert reader("gdrive://abcdefghij", 10) == b"matrix"
        with pytest.raises(ValueError):
            kwargs["authority"]("other")

    monkeypatch.setattr(host.subprocess, "run", run)
    monkeypatch.setattr(host, "guarded_matrix_authority", authority)
    monkeypatch.setattr(host, "serve", serve)
    host.serve_configured(object(), config)
    assert calls[0][1]["user"] == 1002
    assert calls[0][1]["group"] == 1003
    assert calls[0][1]["extra_groups"] == []
    assert calls[0][1]["timeout"] == 25


def test_deadline_restores_previous_signal_handler_even_when_expired(monkeypatch):
    calls, handler = [], []
    monkeypatch.setattr(host.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(host.signal, "ITIMER_REAL", 0, raising=False)
    monkeypatch.setattr(host.signal, "getsignal", lambda _: "previous")
    monkeypatch.setattr(host.signal, "getitimer", lambda _: (0, 0), raising=False)
    monkeypatch.setattr(
        host.signal,
        "signal",
        lambda number, fn: (calls.append(("signal", fn)), handler.append(fn)),
    )
    monkeypatch.setattr(
        host.signal,
        "setitimer",
        lambda number, seconds: calls.append(("timer", seconds)),
        raising=False,
    )
    with pytest.raises(host.MatrixRequestDeadline), host.request_deadline(55):
        handler[0](14, None)
    assert calls[-2:] == [("timer", 0), ("signal", "previous")]


def test_existing_timer_is_not_overwritten(monkeypatch):
    monkeypatch.setattr(host.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(host.signal, "ITIMER_REAL", 0, raising=False)
    monkeypatch.setattr(host.signal, "getsignal", lambda _: "previous")
    monkeypatch.setattr(host.signal, "getitimer", lambda _: (2, 0), raising=False)
    monkeypatch.setattr(
        host.signal, "setitimer", lambda *a: pytest.fail("timer changed"), raising=False
    )
    with pytest.raises(ValueError, match="already in use"), host.request_deadline(55):
        pass


def test_expired_deadline_is_a_sanitized_failed_service(monkeypatch):
    @contextmanager
    def expired(_seconds):
        raise host.MatrixRequestDeadline()
        yield

    with monkeypatch.context() as patch:
        patch.setattr(host.os, "name", "posix")
        patch.setattr(host.os, "geteuid", lambda: 0, raising=False)
        patch.setattr(host, "request_deadline", expired)
        patch.setattr(sys, "argv", ["matrix-host", "--config", "/unused"])
        with pytest.raises(SystemExit) as result:
            host.main()
    assert result.value.code == "matrix request deadline exceeded"


def test_deadline_during_ack_closes_without_second_response(monkeypatch):
    import socket
    import struct

    state = {"locked": False, "closed": False, "sent": []}
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)

    class Connection:
        family = socket.AF_UNIX
        type = socket.SOCK_STREAM
        incoming = bytearray(b'{"version":"v2"}\n')

        def settimeout(self, value):
            pass

        def getsockopt(self, *args):
            return struct.pack("3i", 99, 123, 123)

        def recv(self, length):
            if not self.incoming:
                raise host.MatrixRequestDeadline()
            result = bytes(self.incoming[:length])
            del self.incoming[:length]
            return result

        def sendall(self, data):
            assert state["locked"]
            state["sent"].append(data)

        def close(self):
            state["closed"] = True

    @contextmanager
    def authority(actor):
        state["locked"] = True
        try:
            yield {}, {}, object()
        finally:
            state["locked"] = False

    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(broker, "read_matrix", lambda **kwargs: "verified")
    with pytest.raises(host.MatrixRequestDeadline):
        broker.serve(
            Connection(), client_uid=123, actor="agent", binding={}, authority=authority
        )
    assert state == {
        "locked": False,
        "closed": True,
        "sent": [b'{"matrix": "verified"}\n'],
    }


@pytest.mark.skipif(os.name != "posix", reason="real POSIX signals and flock required")
def test_host_deadline_interrupts_real_lock_wait_and_releases_prior_lock(tmp_path):
    import fcntl

    first, second = tmp_path / "policy.lock", tmp_path / "manifest.lock"
    first.touch()
    second.touch()
    code = """
import fcntl,os,sys
from phantomdocs import view_matrix_host as host
first_path,second_path=sys.argv[1:]
host.REQUEST_DEADLINE_SECONDS=0.4
host.os.geteuid=lambda:0
host.load_config=lambda path:{}
host.socket.socket=lambda fileno:(os.close(fileno) or object())
def blocked(connection,config):
    with open(first_path,'r+') as first, open(second_path,'r+') as second:
        fcntl.flock(first,fcntl.LOCK_EX)
        print('FIRST_LOCK_HELD',flush=True)
        fcntl.flock(second,fcntl.LOCK_EX)
host.serve_configured=blocked
sys.argv=['matrix-host','--config','/unused']
host.main()
"""
    with second.open("r+") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        started = time.monotonic()
        result = subprocess.run(
            [sys.executable, "-c", code, str(first), str(second)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert result.returncode != 0
        assert "FIRST_LOCK_HELD" in result.stdout
        assert "matrix request deadline exceeded" in result.stderr
        assert time.monotonic() - started < 4
        with first.open("r+") as released:
            fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
