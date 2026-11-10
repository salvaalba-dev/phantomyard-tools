from contextlib import contextmanager
from types import SimpleNamespace

import pytest

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
