"""Linux-only protected UID mapping; no real identities or credentials."""

import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from phantomdocs.workflow_local_identity import resolve_local_actor
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
