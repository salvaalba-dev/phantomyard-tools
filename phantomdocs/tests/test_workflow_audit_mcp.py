import io
import json
import os
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from phantomdocs.workflow_audit_mcp import dispatch, read_evidence, serve


def test_only_fixed_read_operation_is_exposed(monkeypatch):
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_mcp.read_evidence",
        lambda path: {"complete_audit": False},
    )
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "read_review_evidence", "arguments": {}},
    }
    with pytest.raises(ValueError):
        dispatch(request, "/unused")
    assert (
        "complete_audit"
        in dispatch(request, "/unused", lambda evidence: None)["content"][0]["text"]
    )
    request["params"]["arguments"] = {"path": "/etc/passwd"}
    with pytest.raises(ValueError):
        dispatch(request, "/unused")


def test_peer_mode_returns_only_peer_authorized_evidence():
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_review_evidence", "arguments": {}},
    }
    output = io.StringIO()
    serve(
        None,
        io.StringIO(json.dumps(request) + "\n"),
        output,
        evidence_provider=lambda: {"complete_audit": False},
    )
    assert (
        "complete_audit"
        in json.loads(output.getvalue())["result"]["content"][0]["text"]
    )


def test_protocol_returns_error_without_leaking_file_paths():
    source = io.StringIO(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "unknown"},
            }
        )
        + "\n"
    )
    target = io.StringIO()
    serve("/private/path", source, target)
    assert (
        json.loads(target.getvalue())["error"]["message"]
        == "Review evidence unavailable"
    )
    assert "/private/path" not in target.getvalue()


def test_authorization_guard_is_held_during_output(monkeypatch):
    state = {"held": False}

    @contextmanager
    def guard(path):
        state["held"] = True
        try:
            yield lambda evidence: None
        finally:
            state["held"] = False

    class Output(io.StringIO):
        def write(self, text):
            assert state["held"]
            return super().write(text)

    monkeypatch.setattr("phantomdocs.workflow_audit_mcp.guarded_authorizer", guard)
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_mcp.read_evidence",
        lambda path: {"complete_audit": False},
    )
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_review_evidence", "arguments": {}},
    }
    output = Output()
    serve("/unused", io.StringIO(json.dumps(request) + "\n"), output, "/config")
    assert "result" in json.loads(output.getvalue())
    assert state["held"] is False


def test_stdio_process_initializes_and_lists_only_read_tool():
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {}},
        },
    ]
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "phantomdocs.workflow_audit_mcp",
            "--evidence",
            "/unused",
            "--authorization-config",
            "/unused-config",
        ],
        input="".join(json.dumps(item) + "\n" for item in requests),
        capture_output=True,
        text=True,
        check=True,
    )
    replies = [json.loads(line) for line in process.stdout.splitlines()]
    assert replies[0]["result"]["protocolVersion"] == "2024-11-05"
    assert [tool["name"] for tool in replies[1]["result"]["tools"]] == [
        "read_review_evidence"
    ]
    assert "error" in replies[2]


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership boundary")
def test_private_fresh_snapshot_is_read_but_expired_or_public_is_refused():
    import hashlib

    with tempfile.TemporaryDirectory(prefix="audit-test-", dir=Path.home()) as parent:
        from phantomdocs.workflow_audit_collection import collection_guard

        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with collection_guard(directory, os.getuid(), writer=True):
                pass
        finally:
            os.close(directory)
        path = Path(parent) / "evidence.json"
        data = {
            "kind": "document-review-evidence",
            "version": 1,
            "complete_audit": False,
            "created_at": int(time.time()),
            "matrix_text": "matrix",
            "matrix_sha256": hashlib.sha256(b"matrix").hexdigest(),
        }
        path.write_text(json.dumps(data))
        path.chmod(0o600)
        assert read_evidence(path)["matrix_text"] == "matrix"
        path.chmod(0o644)
        with pytest.raises(ValueError):
            read_evidence(path)
        path.chmod(0o600)
        data["created_at"] -= 3601
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError):
            read_evidence(path)
