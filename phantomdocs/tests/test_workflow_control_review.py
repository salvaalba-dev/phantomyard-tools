"""Control reconciliation is review-only and does not infer authority."""

import hashlib
import io
import json
from copy import deepcopy

import pytest
import test_workflow_scan as fixtures
import yaml
from click.testing import CliRunner

from phantomdocs.workflow_control_review import (
    review_control,
    review_control_from_archive,
)
from phantomdocs.workflows import WorkflowError


@pytest.fixture
def system():
    return fixtures.system.__wrapped__()


def check(system, **changes):
    control = {
        "kind": "operator-intake-request",
        "organization": system[6]["manifest"]["org"],
        "source_ref": "gdrive://example-file",
        "sha256": "3" * 64,
        "category": "category-2",
        "owners": ["custodian", "project-lead"],
    }
    control.update(changes.pop("control", {}))
    args = {
        "control": control,
        "observed_sha256": "3" * 64,
        "org": system[2],
        "actor": "coordinator",
        "manifest": system[6],
    }
    args.update(changes)
    return review_control(**args)


def test_match_is_review_only_and_does_not_mutate(system):
    node = fixtures.index(system)
    before = deepcopy(system[6])
    result = check(system)
    assert result == {
        "status": "review-required",
        "execution_ready": False,
        "reason": "matching-evidence",
        "urn": node["urn"],
    }
    assert system[6] == before


def test_different_current_bytes_are_rejected(system):
    fixtures.index(system)
    assert (
        check(system, observed_sha256="4" * 64)["reason"]
        == "current-content-differs-from-request"
    )


def test_unauthorized_actor_learns_no_document_identity(system):
    fixtures.index(system)
    result = check(system, actor="unmapped")
    assert result["reason"] == "reference-unavailable-or-unauthorized"
    assert "urn" not in result


@pytest.mark.parametrize(
    "changes",
    [
        {"category": "category-4"},
        {"owners": ["project-lead"]},
    ],
)
def test_changed_classification_is_not_matched(system, changes):
    fixtures.index(system)
    assert check(system, control=changes)["reason"] == "classification-conflict"


@pytest.mark.parametrize("owners", [None, [], ["a", "a"], ["a", 3]])
def test_invalid_owner_claims_rejected(system, owners):
    fixtures.index(system)
    with pytest.raises(WorkflowError):
        check(system, control={"owners": owners})


def test_historical_version_is_not_considered_current(system):
    old = fixtures.index(system)
    current = deepcopy(old)
    current.update(mac="4" * 64, previous=old["mac"], contentHash="5" * 64)
    system[6]["nodes"].append(current)
    assert check(system)["reason"] == "archive-content-conflict"


def test_multiple_current_documents_with_same_reference_are_ambiguous(system):
    first = fixtures.index(system)
    second = deepcopy(first)
    second.update(
        mac="4" * 64, urn="urn:example-org:doc:project-reports/other", slug="other"
    )
    system[6]["nodes"].append(second)
    result = check(system)
    assert result["reason"] == "ambiguous-archive-reference"
    assert "urn" not in result


def test_broken_current_version_pointer_is_rejected(system):
    node = fixtures.index(system)
    system[6]["currentVersions"] = {node["urn"]: "9" * 64}
    with pytest.raises(WorkflowError, match="invalid or mismatched"):
        check(system)


def test_different_organization_is_rejected(system):
    fixtures.index(system)
    with pytest.raises(WorkflowError, match="invalid or mismatched"):
        check(system, control={"organization": "other-org"})


class ArchiveReader:
    def __init__(
        self, content, *, change=False, declared_size=None, returned_ref="example-file"
    ):
        self.content = content
        self.change = change
        self.declared_size = declared_size
        self.returned_ref = returned_ref
        self.calls = 0
        self.cache = {}

    def metadata(self, ref):
        self.calls += 1
        return {
            "id": "example-file",
            "size": self.declared_size or str(len(self.content)),
            "version": "2" if self.change and self.calls > 1 else "1",
            "trashed": False,
        }

    def read_reference(self, ref, *, streaming):
        assert streaming

        class Snapshot:
            def __init__(self, content):
                self.file = io.BytesIO(content)

            def close(self):
                self.file.close()

        return Snapshot(self.content), {"backend": "gdrive", "ref": self.returned_ref}


def review_archive(system, reader, *, actor="coordinator"):
    digest = hashlib.sha256(b"original").hexdigest()
    node = fixtures.index(system)
    node["contentHash"] = digest
    return review_control_from_archive(
        {
            "kind": "operator-intake-request",
            "organization": "example-org",
            "source_ref": "gdrive://example-file",
            "sha256": digest,
            "category": "category-2",
            "owners": ["custodian", "project-lead"],
        },
        org=system[2],
        actor=actor,
        manifest=system[6],
        reader=reader,
    )


def test_archive_bytes_are_independently_checked(system):
    result = review_archive(system, ArchiveReader(b"original"))
    assert result["reason"] == "matching-evidence"
    assert result["execution_ready"] is False


def test_changed_archive_content_is_not_matched(system):
    assert (
        review_archive(system, ArchiveReader(b"different"))["reason"]
        == "current-content-differs-from-request"
    )


def test_changed_archive_metadata_is_not_matched(system):
    assert (
        review_archive(system, ArchiveReader(b"original", change=True))["reason"]
        == "archive-metadata-changed"
    )


@pytest.mark.parametrize("declared_size", ["0", "1073741825", "9" * 5000, "1.5"])
def test_invalid_archive_size_is_not_read(system, declared_size):
    reader = ArchiveReader(b"original", declared_size=declared_size)
    result = review_archive(system, reader)
    assert result["reason"] == "archive-metadata-unverified"
    assert reader.calls == 1


def test_incomplete_archive_read_is_rejected(system):
    reader = ArchiveReader(b"original", declared_size="9")
    with pytest.raises(WorkflowError, match="size differs"):
        review_archive(system, reader)


def test_reader_must_return_the_requested_archive_reference(system):
    reader = ArchiveReader(b"original", returned_ref="other-file")
    with pytest.raises(WorkflowError, match="different reference"):
        review_archive(system, reader)


def test_denied_actor_does_not_read_archive(system):
    reader = ArchiveReader(b"original")
    assert (
        review_archive(system, reader, actor="unmapped")["reason"]
        == "reference-unavailable-or-unauthorized"
    )
    assert reader.calls == 0


def test_cli_reads_control_only_and_returns_review_status(
    system, tmp_path, monkeypatch
):
    from phantomdocs import cli

    digest = hashlib.sha256(b"original").hexdigest()
    node = fixtures.index(system)
    node["contentHash"] = digest
    root = tmp_path / "store"
    root.mkdir()
    control = tmp_path / "control.json"
    control.write_text(
        json.dumps(
            {
                "kind": "operator-intake-request",
                "organization": "example-org",
                "source_ref": "gdrive://example-file",
                "sha256": digest,
                "category": "category-2",
                "owners": ["custodian", "project-lead"],
            }
        ),
        encoding="utf-8",
    )
    org = tmp_path / "org.yaml"
    org.write_text(yaml.safe_dump(system[2]), encoding="utf-8")
    token = tmp_path / "token"
    token.write_text("synthetic-token", encoding="utf-8")
    before = {path.name: path.read_bytes() for path in (control, org, token)}
    reader = ArchiveReader(b"original")
    monkeypatch.setattr(cli, "_require_acl", lambda *_: ("coordinator", system[2]))
    monkeypatch.setattr(cli, "_load_or_die", lambda _root: system[6])
    # Imports occur inside the command, so replace the source used there too.
    monkeypatch.setattr(
        "phantomdocs.workflow_drive_reader.DriveArchiveReader",
        lambda *args, **kwargs: reader,
    )
    from phantomdocs.cli import main

    result = CliRunner().invoke(
        main,
        [
            "workflow",
            "control-review",
            "--control",
            str(control),
            "--root",
            str(root),
            "--org-yaml",
            str(org),
            "--drive-token-file",
            str(token),
            "--max-bytes",
            "1024",
        ],
    )
    assert result.exit_code == 2, result.output
    assert '"reason": "matching-evidence"' in result.output
    assert {path.name: path.read_bytes() for path in (control, org, token)} == before
    assert list(root.iterdir()) == []
