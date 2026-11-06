"""Reference deduplication stays inside the real service/manifest lock."""

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from click.testing import CliRunner
from test_documents import _repo, _svc

from phantomdocs.cli import main
from phantomdocs.documents import DocumentError, DocumentService

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="Existing store filesystem operations require POSIX"
)


def test_same_drive_ref_is_not_read_or_hashed_twice(tmp_path, monkeypatch):
    root, _, service = _svc(tmp_path)
    calls = []

    def read(ref, **kwargs):
        calls.append(ref)
        return b"meeting text", {"backend": "gdrive", "ref": ref.split("://")[1]}

    monkeypatch.setattr("phantomdocs.storage.read_reference", read)
    args = {
        "ref": "gdrive://existing-drive-id",
        "slug": "meeting",
        "category": "category-1",
        "folder": None,
        "owners": ["cfo"],
    }
    service.index_reference_once(**args)

    def no_hash(*args):
        pytest.fail("existing reference must not be hashed")

    monkeypatch.setattr("phantomdocs.documents.content_hash", no_hash)
    assert service.index_reference_once(**args)["unchanged"]
    assert service.index_reference_once(**{**args, "slug": "other-name"})["unchanged"]
    assert calls == ["gdrive://existing-drive-id"]
    assert len([n for n in _repo(root).data["nodes"] if n["kind"] == "doc"]) == 1
    assert not (tmp_path / "blobs").exists()


def test_reference_policy_conflict_and_slug_collision_are_denied_before_read(
    tmp_path, monkeypatch
):
    _, _, service = _svc(tmp_path)
    monkeypatch.setattr(
        "phantomdocs.storage.read_reference",
        lambda ref, **kw: (b"text", {"backend": "gdrive", "ref": ref.split("://")[1]}),
    )
    args = {
        "ref": "gdrive://file-one",
        "slug": "meeting",
        "category": "category-1",
        "folder": None,
        "owners": ["cfo"],
    }
    service.index_reference_once(**args)
    monkeypatch.setattr(
        "phantomdocs.storage.read_reference",
        lambda *a, **kw: pytest.fail("must refuse before reading"),
    )
    with pytest.raises(DocumentError, match="conflicting"):
        service.index_reference_once(**{**args, "category": "category-2"})
    with pytest.raises(DocumentError, match="another document"):
        service.index_reference_once(**{**args, "ref": "gdrive://file-two"})


def test_concurrent_reference_ingest_has_one_read_and_one_node(tmp_path, monkeypatch):
    root, org, _ = _svc(tmp_path)
    calls = []

    def read(ref, **kw):
        calls.append(ref)
        return b"meeting", {"backend": "gdrive", "ref": "file-one"}

    monkeypatch.setattr("phantomdocs.storage.read_reference", read)

    def index(_):
        return DocumentService(root, org, "roberto").index_reference_once(
            ref="gdrive://file-one",
            slug="meeting",
            category="category-1",
            folder=None,
            owners=["cfo"],
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(index, range(4)))
    assert len(calls) == 1
    assert sum(r.get("unchanged", False) for r in results) == 3
    assert len(_repo(root).data["nodes"]) == 1


def test_distinct_reference_with_same_content_is_held_without_a_second_read(tmp_path):
    root, _, service = _svc(tmp_path)
    data = b"synthetic original"
    checksum = hashlib.sha256(data).hexdigest()
    calls = []

    def read(ref, **kwargs):
        calls.append(ref)
        return data, {"backend": "gdrive", "ref": ref.split("://")[1]}

    args = {
        "ref": "gdrive://first",
        "slug": "first",
        "category": "category-1",
        "folder": None,
        "owners": ["cfo"],
        "expected_hash": checksum,
        "reader": read,
        "hold_matching_content": True,
    }
    service.index_reference_once(**args)
    with pytest.raises(DocumentError, match="review required"):
        service.index_reference_once(
            **{**args, "ref": "gdrive://second", "slug": "second"}
        )
    assert calls == ["gdrive://first"]
    assert len([n for n in _repo(root).data["nodes"] if n["kind"] == "doc"]) == 1
    assert service.index_reference_once(**args)["unchanged"]


def test_concurrent_distinct_refs_with_same_content_leave_one_node(tmp_path):
    root, org, _ = _svc(tmp_path)
    data = b"concurrent synthetic original"
    checksum = hashlib.sha256(data).hexdigest()

    def run(number):
        def read(ref, **kwargs):
            return data, {"backend": "gdrive", "ref": ref.split("://")[1]}

        service = DocumentService(root, org, "roberto")
        try:
            service.index_reference_once(
                ref=f"gdrive://file-{number}",
                slug=f"file-{number}",
                category="category-1",
                folder=None,
                owners=["cfo"],
                expected_hash=checksum,
                reader=read,
                hold_matching_content=True,
            )
            return "indexed"
        except DocumentError as exc:
            assert "review required" in str(exc)
            return "held"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, (1, 2)))
    assert sorted(results) == ["held", "indexed"]
    assert len([n for n in _repo(root).data["nodes"] if n["kind"] == "doc"]) == 1


def test_match_to_historical_version_holds_new_reference(tmp_path):
    root, _, service = _svc(tmp_path)
    for data in (b"old synthetic bytes", b"new synthetic bytes"):
        service.add_document(
            content=data,
            ref_location=None,
            slug="original",
            category="category-1",
            folder=None,
            owners=["cfo"],
            backend=None,
        )
    assert len(_repo(root).versions_of("urn:org:doc:original")) == 2

    def no_read(*args, **kwargs):
        pytest.fail("historical match must be held before reading")

    with pytest.raises(DocumentError, match="review required"):
        service.index_reference_once(
            ref="gdrive://copy",
            slug="copy",
            category="category-1",
            folder=None,
            owners=["cfo"],
            expected_hash=hashlib.sha256(b"old synthetic bytes").hexdigest(),
            reader=no_read,
            hold_matching_content=True,
        )
    assert len(_repo(root).versions_of("urn:org:doc:original")) == 2


def test_cli_reference_skip_uses_real_service_without_copying(tmp_path, monkeypatch):
    root, org, _ = _svc(tmp_path)
    calls = []

    def read(ref, **kw):
        calls.append(ref)
        return b"record", {"backend": "gdrive", "ref": "file-one"}

    monkeypatch.setattr("phantomdocs.storage.read_reference", read)
    args = [
        "add",
        "--ref",
        "gdrive://file-one",
        "--skip-existing-ref",
        "--slug",
        "meeting",
        "--category",
        "1",
        "--owners",
        "cfo",
        "--actor",
        "roberto",
        "--org-yaml",
        org,
        "--root",
        root,
    ]
    runner = CliRunner()
    first = runner.invoke(main, args)
    assert first.exit_code == 0, first.output
    second = runner.invoke(main, args)
    assert second.exit_code == 0, second.output
    assert "unchanged" in second.output and len(calls) == 1


def test_nested_folder_slug_matches_path_and_retry_skips_reader(tmp_path):
    root, _, service = _svc(tmp_path)
    service.create_folder(name="projects", parent=None, category="1", owners=["cfo"])
    service.create_folder(
        name="minutes", parent="projects", category="1", owners=["cfo"]
    )
    calls = []

    def read(ref, **kwargs):
        calls.append(ref)
        return b"minutes", {"backend": "gdrive", "ref": "file-one"}

    args = {
        "ref": "gdrive://file-one",
        "slug": "meeting",
        "category": "1",
        "owners": ["cfo"],
        "reader": read,
    }
    service.index_reference_once(**args, folder="minutes")
    assert service.index_reference_once(**args, folder="projects/minutes")["unchanged"]
    assert service.index_reference_once(**args, folder="minutes")["unchanged"]
    assert calls == ["gdrive://file-one"]
    assert len([n for n in _repo(root).data["nodes"] if n["kind"] == "doc"]) == 1
