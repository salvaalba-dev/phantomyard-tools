"""The CLI fallback binds its target and claimed actor to the peer response."""

import hashlib
import io
import os

import pytest
from click.testing import CliRunner

from phantomdocs import workflow_admission_search as search
from phantomdocs.cli import main
from phantomdocs.content import FileContent


@pytest.fixture
def config(monkeypatch, tmp_path):
    value = {
        "org_path": str(tmp_path / "org.yaml"),
        "store_path": str(tmp_path / "store"),
        "socket_path": str(tmp_path / "socket"),
        "server_uid": 123,
    }
    monkeypatch.setattr(search, "load_config", lambda _: value)
    return value


def test_accepts_only_authenticated_actor_and_configured_target(monkeypatch, config):
    seen = []

    def request(*args):
        seen.append(args)
        return {
            "status": "ok",
            "actor": "reader",
            "items": [{"kind": "doc", "urn": "urn:example:doc:report"}],
        }

    monkeypatch.setattr(search, "request_peer", request)
    result = search.search_configured(
        "report", actor="reader", org_yaml=config["org_path"], root=config["store_path"]
    )
    assert result == [{"kind": "doc", "urn": "urn:example:doc:report"}]
    assert seen == [(config["socket_path"], 123, {"search": {"query": "report"}})]
    with pytest.raises(Exception, match="protected search unavailable or denied"):
        search.search_configured(
            "report",
            actor="other",
            org_yaml=config["org_path"],
            root=config["store_path"],
        )
    with pytest.raises(Exception, match="protected search unavailable or denied"):
        search.search_configured(
            "report",
            actor="reader",
            org_yaml=config["org_path"],
            root=os.path.abspath("other"),
        )
    assert len(seen) == 2  # mismatched target did not contact the service


def test_cli_falls_back_when_manifest_is_inaccessible(monkeypatch, config, tmp_path):
    marker = tmp_path / "protected-config"
    marker.touch()
    monkeypatch.setattr(search, "DEFAULT_CONFIG", str(marker))
    monkeypatch.setattr(
        search,
        "request_peer",
        lambda *_: {
            "status": "ok",
            "actor": "reader",
            "items": [{"kind": "doc", "urn": "urn:example:doc:report"}],
        },
    )
    result = CliRunner().invoke(
        main,
        [
            "search",
            "report",
            "--actor",
            "reader",
            "--org-yaml",
            config["org_path"],
            "--root",
            config["store_path"],
        ],
    )
    assert result.exit_code == 0, result.output
    assert "urn:example:doc:report" in result.output


def test_rejects_terminal_controls(monkeypatch, config):
    monkeypatch.setattr(
        search,
        "request_peer",
        lambda *_: {
            "status": "ok",
            "actor": "reader",
            "items": [{"kind": "doc", "urn": "bad\x1b[0m"}],
        },
    )
    with pytest.raises(Exception, match="protected search unavailable or denied"):
        search.search_configured(
            "", actor="reader", org_yaml=config["org_path"], root=config["store_path"]
        )


@pytest.mark.parametrize("command", ["get", "versions"])
def test_cli_metadata_lookups_use_the_authenticated_peer(
    monkeypatch, config, tmp_path, command
):
    marker = tmp_path / "protected-config"
    marker.touch()
    monkeypatch.setattr(search, "DEFAULT_CONFIG", str(marker))

    def request(_path, _uid, payload):
        operation = payload["lookup"]["operation"]
        result = (
            {"urn": "urn:example:doc:report", "location": "gdrive://example"}
            if operation == "reference"
            else [{"mac": "a" * 64, "size": 4, "current": True}]
        )
        return {"status": "ok", "actor": "reader", "result": result}

    monkeypatch.setattr(search, "request_peer", request)
    result = CliRunner().invoke(
        main,
        [
            command,
            "report",
            "--actor",
            "reader",
            "--org-yaml",
            config["org_path"],
            "--root",
            config["store_path"],
        ],
    )
    assert result.exit_code == 0, result.output
    assert ("gdrive://example" if command == "get" else "(current)") in result.output


def test_peer_get_denies_unavailable_content(monkeypatch, config, tmp_path):
    marker = tmp_path / "protected-config"
    marker.touch()
    monkeypatch.setattr(search, "DEFAULT_CONFIG", str(marker))
    monkeypatch.setattr(search, "request_peer", lambda *_: {"status": "rejected"})
    result = CliRunner().invoke(
        main,
        [
            "get",
            "report",
            "--cat",
            "--actor",
            "reader",
            "--org-yaml",
            config["org_path"],
            "--root",
            config["store_path"],
        ],
    )
    assert result.exit_code != 0
    assert "protected search unavailable or denied" in result.output


def test_reference_rejects_terminal_controls(monkeypatch, config):
    monkeypatch.setattr(
        search,
        "request_peer",
        lambda *_: {
            "status": "ok",
            "actor": "reader",
            "result": {"urn": "urn:example:doc:report", "location": "bad\x1b[0m"},
        },
    )
    with pytest.raises(Exception, match="protected lookup unavailable or denied"):
        search.lookup_configured(
            "reference",
            "report",
            actor="reader",
            org_yaml=config["org_path"],
            root=config["store_path"],
        )


def test_content_uses_callers_drive_and_revalidates_before_returning(
    monkeypatch, config
):
    content_bytes = b"synthetic content"
    details = {
        "urn": "urn:example:doc:report",
        "location": "gdrive://synthetic-file",
        "contentHash": hashlib.sha256(content_bytes).hexdigest(),
        "mac": "a" * 64,
    }
    calls = []

    def lookup(*args, **kwargs):
        calls.append((args, kwargs))
        return dict(details)

    monkeypatch.setattr(search, "lookup_configured", lookup)
    monkeypatch.setattr(
        "phantomdocs.storage._gdrive_download",
        lambda _workspace, file_id, streaming: FileContent.from_stream(
            io.BytesIO(content_bytes)
        ),
    )
    actual, content = search.read_scoped_drive_content(
        "report", actor="reader", org_yaml=config["org_path"], root=config["store_path"]
    )
    with content:
        output = io.BytesIO()
        content.copy_to(output)
    assert actual == details and output.getvalue() == content_bytes
    assert len(calls) == 2


def test_content_hash_mismatch_returns_no_content(monkeypatch, config):
    details = {
        "urn": "urn:example:doc:report",
        "location": "gdrive://synthetic-file",
        "contentHash": "b" * 64,
        "mac": "a" * 64,
    }
    monkeypatch.setattr(search, "lookup_configured", lambda *_a, **_k: dict(details))
    monkeypatch.setattr(
        "phantomdocs.storage._gdrive_download",
        lambda *_a, **_k: FileContent.from_stream(io.BytesIO(b"different")),
    )
    with pytest.raises(Exception, match="protected content unavailable or changed"):
        search.read_scoped_drive_content(
            "report",
            actor="reader",
            org_yaml=config["org_path"],
            root=config["store_path"],
        )


def test_revoked_or_changed_access_discards_the_snapshot(monkeypatch, config):
    details = {
        "urn": "urn:example:doc:report",
        "location": "gdrive://synthetic-file",
        "contentHash": "b" * 64,
        "mac": "a" * 64,
    }
    replies = iter([details, {**details, "mac": "c" * 64}])
    captured = FileContent.from_stream(io.BytesIO(b"synthetic"))
    monkeypatch.setattr(search, "lookup_configured", lambda *_a, **_k: next(replies))
    monkeypatch.setattr(search, "read_location", lambda *_a, **_k: captured)
    with pytest.raises(Exception, match="protected content unavailable or changed"):
        search.read_scoped_drive_content(
            "report",
            actor="reader",
            org_yaml=config["org_path"],
            root=config["store_path"],
        )
    assert captured.file.closed


def test_revoked_access_discards_snapshot_without_output(monkeypatch, config):
    import click

    details = {
        "urn": "urn:example:doc:report",
        "location": "gdrive://synthetic-file",
        "contentHash": "b" * 64,
        "mac": "a" * 64,
    }
    calls = []

    def lookup(*_a, **_k):
        calls.append(True)
        if len(calls) == 2:
            raise click.ClickException("access revoked")
        return details

    captured = FileContent.from_stream(io.BytesIO(b"synthetic"))
    monkeypatch.setattr(search, "lookup_configured", lookup)
    monkeypatch.setattr(search, "read_location", lambda *_a, **_k: captured)
    with pytest.raises(click.ClickException, match="access revoked"):
        search.read_scoped_drive_content(
            "report",
            actor="reader",
            org_yaml=config["org_path"],
            root=config["store_path"],
        )
    assert captured.file.closed


def test_cli_cat_returns_verified_snapshot(monkeypatch, config, tmp_path):
    marker = tmp_path / "protected-config"
    marker.touch()
    monkeypatch.setattr(search, "DEFAULT_CONFIG", str(marker))
    snapshot = FileContent.from_stream(io.BytesIO(b"synthetic bytes"))
    monkeypatch.setattr(
        search,
        "read_scoped_drive_content",
        lambda *_a, **_k: (
            {"urn": "urn:example:doc:report", "location": "gdrive://synthetic"},
            snapshot,
        ),
    )
    result = CliRunner().invoke(
        main,
        [
            "get",
            "report",
            "--cat",
            "--actor",
            "reader",
            "--org-yaml",
            config["org_path"],
            "--root",
            config["store_path"],
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.stdout_bytes.endswith(b"synthetic bytes")
    assert snapshot.file.closed
