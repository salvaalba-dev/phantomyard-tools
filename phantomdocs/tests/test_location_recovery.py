"""Location recovery, operation failure, and digest reuse regressions."""

import io
from unittest import mock

import pytest
import yaml
from test_smoke import _org, _run

from phantomdocs.content import FileContent
from phantomdocs.identity import (
    content_hash,
    doc_version_mac,
    doc_version_mac_from_hash,
)
from phantomdocs.storage import StorageError, _run_checked, read_location


def add(root, org, source, backend=None):
    args = [
        "add",
        str(source),
        "--slug",
        "x.txt",
        "--owners",
        "cfo",
        "--org-yaml",
        org,
        "--root",
        str(root),
    ]
    if backend:
        args += ["--backend", backend]
    result = _run(args)
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("replica", ["missing", "corrupt", "empty", "all-missing"])
def test_separate_local_store_and_rollback_replicas(tmp_path, replica):
    root = tmp_path / "manifest"
    root.mkdir()
    org = _org(tmp_path)
    assert _run(["init", "--org", "demo", "--root", str(root)]).exit_code == 0
    source = tmp_path / "x.txt"
    for content in ("old", "new"):
        source.write_text(content)
        add(root, org, source, str(tmp_path / "separate store"))
    assert _run(["verify", "--root", str(root)]).exit_code == 0
    path = root / "manifest.yaml"
    manifest = yaml.safe_load(path.read_text())
    old = manifest["nodes"][0]
    good = old["locations"][0]
    bad_path = tmp_path / "bad"
    if replica == "corrupt":
        bad_path.write_text("wrong")
    bad = {"backend": "file", "ref": str(bad_path)}
    old["locations"] = [] if replica == "empty" else [bad]
    if replica in ("missing", "corrupt"):
        old["locations"].append(good)
    path.write_text(yaml.safe_dump(manifest, sort_keys=False))
    before = path.read_bytes()
    audit = (root / "audit.log").read_bytes()
    result = _run(
        [
            "rollback",
            old["urn"],
            "--to-mac",
            old["mac"],
            "--org-yaml",
            org,
            "--root",
            str(root),
        ]
    )
    if replica in ("empty", "all-missing"):
        assert result.exit_code != 0
        assert "Error: rollback failed:" in result.output
        assert path.read_bytes() == before
        assert (root / "audit.log").read_bytes() == audit
    else:
        assert result.exit_code == 0, result.output
        nodes = yaml.safe_load(path.read_text())["nodes"]
        assert len(nodes) == 3
        assert nodes[-1]["previous"] == nodes[1]["mac"]
        assert nodes[-1]["mac"] not in (nodes[0]["mac"], nodes[1]["mac"])
        result = _run(["get", "x.txt", "--cat", "--org-yaml", org, "--root", str(root)])
        assert result.exit_code == 0, result.output
        assert "old" in result.output


def test_add_disk_full_is_readable_and_does_not_commit(tmp_path):
    org = _org(tmp_path)
    assert _run(["init", "--org", "demo", "--root", str(tmp_path)]).exit_code == 0
    source = tmp_path / "input"
    source.write_text("content")
    before = (tmp_path / "manifest.yaml").read_bytes()
    with mock.patch.object(
        FileContent, "from_stream", side_effect=OSError(28, "disk full")
    ):
        result = _run(
            [
                "add",
                str(source),
                "--slug",
                "x.txt",
                "--owners",
                "cfo",
                "--org-yaml",
                org,
                "--root",
                str(tmp_path),
            ]
        )
    assert result.exit_code != 0
    assert "Error: add failed:" in result.output
    assert "disk full" in result.output
    assert (tmp_path / "manifest.yaml").read_bytes() == before


def test_hash_read_failure_closes_snapshot(tmp_path):
    snapshot = FileContent.from_stream(io.BytesIO(b"data"))
    with (
        mock.patch("phantomdocs.storage.read_reference", return_value=(snapshot, {})),
        mock.patch.object(FileContent, "digest", side_effect=OSError("read failed")),
        pytest.raises(StorageError, match="read failed"),
    ):
        read_location(
            {"backend": "file", "ref": "unused"},
            "a" * 64,
            root=str(tmp_path),
            streaming=True,
        )
    assert snapshot.file.closed


def test_missing_executable_has_storage_error(tmp_path):
    with pytest.raises(StorageError, match="_run_checked failed"):
        _run_checked([str(tmp_path / "absent-executable")])


def test_digest_mac_matches_bytes_and_add_hashes_once(tmp_path):
    payload = b"example"
    for previous in (None, "b" * 64):
        assert doc_version_mac_from_hash(
            "a" * 64, previous, "x.txt", content_hash(payload)
        ) == doc_version_mac("a" * 64, previous, "x.txt", payload)
    org = _org(tmp_path)
    assert _run(["init", "--org", "demo", "--root", str(tmp_path)]).exit_code == 0
    source = tmp_path / "input"
    source.write_bytes(payload)
    original = FileContent.digest
    calls = []

    def digest(self):
        calls.append(self)
        return original(self)

    with mock.patch.object(FileContent, "digest", digest):
        add(tmp_path, org, source)
    assert len(calls) == 1
