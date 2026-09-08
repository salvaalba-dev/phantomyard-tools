"""Location recovery, operation failure, and digest reuse regressions."""

import io
import shutil
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
from phantomdocs.storage import (
    LocalBackend,
    StorageError,
    _run_checked,
    read_location,
    resolve_backend,
)


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


@pytest.mark.parametrize("explicit", [False, True])
def test_backup_restore_reads_history_without_rewriting_locations(tmp_path, explicit):
    original = tmp_path / "original"
    original.mkdir()
    org = _org(tmp_path)
    assert _run(["init", "--org", "demo", "--root", str(original)]).exit_code == 0
    source = tmp_path / "input"
    for value in ("old version", "current version"):
        source.write_text(value)
        add(original, org, source)
    copied = tmp_path / "backup"
    shutil.copytree(original, copied)
    original_nodes = yaml.safe_load((copied / "manifest.yaml").read_text())["nodes"]
    # Only the original test blobs are removed; backup and manifest are intact.
    for node in original_nodes:
        blob = original / "blobs" / node["contentHash"][:2] / node["contentHash"]
        blob.unlink()
    if explicit:
        manifest_root = tmp_path / "manifest only"
        manifest_root.mkdir()
        for name in ("manifest.yaml", "audit.log"):
            shutil.copyfile(copied / name, manifest_root / name)
        backend_args = ["--backend", str(copied)]
    else:
        manifest_root = copied
        backend_args = []
    common = ["--root", str(manifest_root), *backend_args]
    for extra, value in (
        ([], "current version"),
        (["--mac", original_nodes[0]["mac"]], "old version"),
    ):
        result = _run(["get", "x.txt", "--cat", "--org-yaml", org, *extra, *common])
        assert result.exit_code == 0, result.output
        assert value in result.output
    result = _run(["verify", *common])
    assert result.exit_code == 0, result.output
    assert (
        yaml.safe_load((manifest_root / "manifest.yaml").read_text())["nodes"]
        == original_nodes
    )
    result = _run(
        [
            "rollback",
            "x.txt",
            "--to-mac",
            original_nodes[0]["mac"],
            "--org-yaml",
            org,
            *common,
        ]
    )
    assert result.exit_code == 0, result.output
    nodes = yaml.safe_load((manifest_root / "manifest.yaml").read_text())["nodes"]
    assert nodes[:2] == original_nodes
    assert nodes[2]["previous"] == nodes[1]["mac"]
    assert nodes[2]["contentHash"] == nodes[0]["contentHash"]
    assert _run(["verify", *common]).exit_code == 0


@pytest.mark.parametrize(
    "location",
    [
        {"backend": "ssh", "path": "ssh://example.test:bad/blob"},
        {"backend": "ssh", "path": "ssh://example.test:70000/blob"},
        {"backend": "ssh", "path": "ssh://[broken/blob"},
        {"backend": "ssh", "path": "ssh:///blob"},
        {"backend": "file", "ref": None},
        {"backend": [], "path": "unused"},
    ],
)
def test_malformed_replica_falls_back_and_verify_reports_it(tmp_path, location):
    org = _org(tmp_path)
    assert _run(["init", "--org", "demo", "--root", str(tmp_path)]).exit_code == 0
    source = tmp_path / "input"
    for value in ("old", "current"):
        source.write_text(value)
        add(tmp_path, org, source)
    path = tmp_path / "manifest.yaml"
    manifest = yaml.safe_load(path.read_text())
    old = manifest["nodes"][0]
    old["locations"].insert(0, location)
    path.write_text(yaml.safe_dump(manifest, sort_keys=False))
    with mock.patch(
        "phantomdocs.storage._run_checked",
        side_effect=AssertionError("invalid URI must not start SSH"),
    ):
        result = _run(
            [
                "get",
                "x.txt",
                "--mac",
                old["mac"],
                "--cat",
                "--org-yaml",
                org,
                "--root",
                str(tmp_path),
            ]
        )
        assert result.exit_code == 0, result.output
        assert "old" in result.output
        result = _run(["verify", "--root", str(tmp_path)])
        assert result.exit_code != 0
        assert "location 1 read failed:" in result.output
        assert "1 node(s) failed verification" in result.output
        result = _run(
            [
                "rollback",
                "x.txt",
                "--to-mac",
                old["mac"],
                "--org-yaml",
                org,
                "--root",
                str(tmp_path),
            ]
        )
        assert result.exit_code == 0, result.output


@pytest.mark.parametrize("stage", ["heading", "content"])
def test_get_output_failure_closes_snapshot(tmp_path, stage):
    org = _org(tmp_path)
    assert _run(["init", "--org", "demo", "--root", str(tmp_path)]).exit_code == 0
    source = tmp_path / "input"
    source.write_text("data")
    add(tmp_path, org, source)
    with FileContent.from_stream(io.BytesIO(b"data")) as snapshot:
        target = (
            "phantomdocs.cli.click.echo"
            if stage == "heading"
            else "phantomdocs.content.FileContent.copy_to"
        )
        with (
            mock.patch(
                "phantomdocs.cli._read_document_from_locations",
                return_value=(snapshot, {"backend": "file", "ref": str(source)}),
            ),
            mock.patch(target, side_effect=OSError("output full")),
        ):
            result = _run(
                ["get", "x.txt", "--cat", "--org-yaml", org, "--root", str(tmp_path)]
            )
        assert result.exit_code != 0
        assert snapshot.file.closed


def test_invalid_backend_uri_is_storage_error():
    with pytest.raises(StorageError, match="invalid.*URI"):
        resolve_backend("ssh://host:bad/store")


def test_recovery_does_not_hide_corrupt_present_blob(tmp_path):
    data = b"intact backup"
    digest = content_hash(data)
    primary = LocalBackend(str(tmp_path / "primary"))
    backup = LocalBackend(str(tmp_path / "backup"))
    path = primary.put(digest, data)
    backup.put(digest, data)
    with open(path, "wb") as output:
        output.write(b"corrupted original")
    location = {"backend": "local", "path": path}
    with pytest.raises(StorageError, match="content hash mismatch"):
        read_location(location, digest, root=backup.root, streaming=True)
    # Redirecting to a backup must be explicit when the original is present.
    with read_location(
        location, digest, root=primary.root, backend=backup.root, streaming=True
    ) as restored:
        assert content_hash(restored) == digest


def test_backend_override_does_not_redirect_references(tmp_path):
    source = tmp_path / "external.txt"
    source.write_bytes(b"external")
    with (
        mock.patch(
            "phantomdocs.storage.resolve_backend",
            side_effect=AssertionError("reference must stay pinned"),
        ),
        read_location(
            {"backend": "file", "ref": str(source)},
            content_hash(b"external"),
            root=str(tmp_path),
            backend="ssh://unused/store",
            streaming=True,
        ) as data,
    ):
        assert content_hash(data) == content_hash(b"external")


def test_bad_restore_blob_is_rejected(tmp_path):
    data = b"intact"
    digest = content_hash(data)
    missing = LocalBackend(str(tmp_path / "old"))
    backup = LocalBackend(str(tmp_path / "restored"))
    path = backup.put(digest, data)
    with open(path, "wb") as output:
        output.write(b"damaged backup")
    with pytest.raises(StorageError, match="content hash mismatch"):
        read_location(
            {"backend": "local", "path": missing.blob_path(digest)},
            digest,
            root=backup.root,
            streaming=True,
        )


@pytest.mark.parametrize("backend", ["file", "gdrive"])
def test_verify_reports_reference_location_without_ref(tmp_path, backend):
    org = _org(tmp_path)
    root = str(tmp_path)
    assert _run(["init", "--org", "demo", "--root", root]).exit_code == 0
    source = tmp_path / "x.txt"
    source.write_text("local content")
    add(tmp_path, org, source)
    path = tmp_path / "manifest.yaml"
    manifest = yaml.safe_load(path.read_text())
    manifest["nodes"][0]["locations"].append(
        {"backend": backend, "path": "missing-remote-object"}
    )
    path.write_text(yaml.safe_dump(manifest, sort_keys=False))
    result = _run(["verify", "--root", root])
    assert result.exit_code != 0
    assert f"location 2 read failed: {backend} location requires a ref" in result.output
