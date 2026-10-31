"""Reconciliation returns review evidence, never permission to mutate data."""

import hashlib
import io
from copy import deepcopy

import pytest
import test_workflow_scan as scan_fixtures

from phantomdocs.workflow_reconcile import review_copy, review_receipt
from phantomdocs.workflows import WorkflowError


@pytest.fixture
def system():
    return scan_fixtures.system.__wrapped__()


index = scan_fixtures.index


def check(system, **changes):
    arguments = {
        "inbox_ref": "gdrive://intake-copy",
        "archive_ref": "gdrive://example-file",
        "receipt_inbox_ref": "gdrive://intake-copy",
        "receipt_archive_ref": "gdrive://example-file",
        "observed_sha256": "3" * 64,
        "receipt_sha256": "3" * 64,
        "org": system[2],
        "caller": "coordinator",
        "manifest": system[6],
    }
    arguments.update(changes)
    return review_copy(**arguments)


def test_matching_evidence_remains_review_only(system):
    node = index(system)
    result = check(system)
    assert result == {
        "status": "review-required",
        "execution_ready": False,
        "reason": "matching-evidence",
        "urn": node["urn"],
    }


def test_changed_copy_does_not_match(system):
    index(system)
    assert (
        check(system, observed_sha256="4" * 64)["reason"]
        == "current-content-differs-from-receipt"
    )


def test_digest_does_not_prove_archive_identity(system):
    index(system)
    assert (
        check(system, archive_ref="gdrive://other-file")["reason"]
        == "receipt-reference-conflict"
    )


def test_receipt_for_another_copy_is_not_accepted(system):
    index(system)
    assert (
        check(system, receipt_inbox_ref="gdrive://other-copy")["reason"]
        == "receipt-reference-conflict"
    )


def test_denied_actor_does_not_learn_identity(system):
    index(system)
    result = check(system, caller="unmapped")
    assert result["reason"] == "reference-unavailable-or-unauthorized"
    assert "urn" not in result


def test_reference_with_multiple_identities_requires_review(system):
    node = index(system)
    other = deepcopy(node)
    other.update(
        mac="4" * 64, urn="urn:example-org:doc:project-reports/other", slug="other"
    )
    system[6]["nodes"].append(other)
    result = check(system)
    assert result["reason"] == "ambiguous-archive-reference"
    assert "urn" not in result


def test_archive_hash_mismatch_is_not_a_match(system):
    node = index(system)
    node["contentHash"] = "4" * 64
    assert check(system)["reason"] == "archive-content-conflict"


def test_invalid_digest_rejected(system):
    with pytest.raises(WorkflowError, match="digest"):
        check(system, observed_sha256="not-a-hash")


class FakeReader:
    def __init__(self, content, *, parent="shared-intake", change=False):
        self.content, self.parent, self.change = content, parent, change
        self.cache = {}
        self.calls = 0

    def metadata(self, ref):
        self.calls += 1
        return {
            "id": "intake-copy",
            "parents": [self.parent],
            "size": str(len(self.content)),
            "version": "1",
            "trashed": False,
            "md5Checksum": "x" if self.change and self.calls > 1 else "y",
        }

    def read_reference(self, ref, *, streaming):
        assert streaming

        class Snapshot:
            def __init__(self, data):
                self.file = io.BytesIO(data)

            def close(self):
                self.file.close()

        return Snapshot(self.content), {"backend": "gdrive", "ref": "intake-copy"}


def review_with_reader(system, reader):
    node = index(system)
    digest = hashlib.sha256(b"same bytes").hexdigest()
    node["contentHash"] = digest
    return review_receipt(
        receipt={
            "inbox_ref": "gdrive://intake-copy",
            "archive_ref": "gdrive://example-file",
            "sha256": digest,
        },
        inbox_ref="gdrive://intake-copy",
        inbox_name="coordinator",
        org=system[2],
        caller="coordinator",
        manifest=system[6],
        reader=reader,
    )


def test_provider_bytes_confirm_only_review_evidence(system):
    reader = FakeReader(b"same bytes")
    result = review_with_reader(system, reader)
    assert result["reason"] == "matching-evidence"
    assert result["execution_ready"] is False and reader.calls >= 2


def test_repeated_review_does_not_mutate_the_manifest(system):
    reader = FakeReader(b"same bytes")
    first = review_with_reader(system, reader)
    manifest = deepcopy(system[6])
    result = review_receipt(
        receipt={
            "inbox_ref": "gdrive://intake-copy",
            "archive_ref": "gdrive://example-file",
            "sha256": hashlib.sha256(b"same bytes").hexdigest(),
        },
        inbox_ref="gdrive://intake-copy",
        inbox_name="coordinator",
        org=system[2],
        caller="coordinator",
        manifest=system[6],
        reader=reader,
    )
    assert result == first and system[6] == manifest


def test_modified_provider_bytes_are_not_a_match(system):
    assert (
        review_with_reader(system, FakeReader(b"other bytes"))["reason"]
        == "current-content-differs-from-receipt"
    )


def test_moved_file_is_not_read(system):
    reader = FakeReader(b"same bytes", parent="elsewhere")
    assert review_with_reader(system, reader)["reason"] == "inbox-membership-unverified"
    assert reader.calls == 1


def test_changing_provider_metadata_requires_review(system):
    assert (
        review_with_reader(system, FakeReader(b"same bytes", change=True))["reason"]
        == "inbox-metadata-changed"
    )


def test_denied_actor_does_not_read_provider_bytes(system):
    node = index(system)
    digest = hashlib.sha256(b"same bytes").hexdigest()
    node["contentHash"] = digest
    reader = FakeReader(b"same bytes")
    result = review_receipt(
        receipt={
            "inbox_ref": "gdrive://intake-copy",
            "archive_ref": "gdrive://example-file",
            "sha256": digest,
        },
        inbox_ref="gdrive://intake-copy",
        inbox_name="coordinator",
        org=system[2],
        caller="unmapped",
        manifest=system[6],
        reader=reader,
    )
    assert result["reason"] == "reference-unavailable-or-unauthorized"
    assert reader.calls == 0
