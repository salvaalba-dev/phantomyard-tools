"""Unknown legacy history is never equivalent to an empty committed audit log."""

import copy

import pytest
import yaml
from click.testing import CliRunner

from phantomdocs import audit
from phantomdocs.cli import main
from phantomdocs.documents import DocumentError, DocumentService
from phantomdocs.identity import root_mac
from phantomdocs.manifest import ManifestRepository, empty_manifest


def _legacy_log(root, count=3):
    for index in range(count):
        audit.append(
            str(root),
            "sample-actor",
            "add",
            "urn:sample-org:doc:sample.txt",
            f"{index + 1:064x}",
            None,
        )
    return (root / "audit.log").read_bytes()


def _repo():
    return ManifestRepository(
        empty_manifest("sample-org", "docs", root_mac("sample-org", "", "docs"))
    )


def _service(root):
    # Exercise reconciliation plumbing without unrelated key-file/platform setup.
    service = DocumentService.__new__(DocumentService)
    service.root = str(root)
    service.nsec = None
    return service


@pytest.mark.parametrize("missing", [True, False])
def test_mutation_preserves_unanchored_legacy_audit(tmp_path, monkeypatch, missing):
    original = _legacy_log(tmp_path)
    repo = _repo()
    if missing:
        repo.data["manifest"].pop("auditSeq")
        repo.data["manifest"].pop("auditHead")
    else:
        repo.data["manifest"]["auditSeq"] = None
    before = copy.deepcopy(repo.data)
    monkeypatch.setattr(
        audit,
        "truncate",
        lambda *_args: pytest.fail("legacy history must not be truncated"),
    )
    with pytest.raises(
        DocumentError, match="legacy audit log has no manifest checkpoint"
    ):
        _service(tmp_path)._next_head(repo)
    assert (tmp_path / "audit.log").read_bytes() == original
    assert repo.data == before


def test_legacy_store_without_an_audit_log_does_not_require_recovery(tmp_path):
    repo = _repo()
    repo.data["manifest"].pop("auditSeq")
    repo.data["manifest"].pop("auditHead")
    _service(tmp_path)._reconcile_audit(repo)
    assert list(tmp_path.iterdir()) == []


def test_complete_checkpoint_preserves_legacy_entries(tmp_path):
    original = _legacy_log(tmp_path)
    repo = _repo()
    count, head = audit.head(str(tmp_path))
    repo.data["manifest"].update(auditSeq=count, auditHead=head)
    _service(tmp_path)._reconcile_audit(repo)
    assert (tmp_path / "audit.log").read_bytes() == original


@pytest.mark.parametrize("count", [-1, False, True, 1.0, "1", None])
def test_invalid_checkpoint_count_never_truncates(tmp_path, monkeypatch, count):
    original = _legacy_log(tmp_path)
    _, head = audit.head(str(tmp_path))
    monkeypatch.setattr(
        audit,
        "truncate",
        lambda *_args: pytest.fail("invalid checkpoint must not truncate"),
    )
    with pytest.raises(ValueError, match="checkpoint count"):
        audit.reconcile(str(tmp_path), count, head)
    assert (tmp_path / "audit.log").read_bytes() == original


@pytest.mark.parametrize("head", [None, "", "short", 1])
def test_nonempty_checkpoint_requires_head_hash(tmp_path, monkeypatch, head):
    original = _legacy_log(tmp_path)
    monkeypatch.setattr(
        audit,
        "truncate",
        lambda *_args: pytest.fail("incomplete checkpoint must not truncate"),
    )
    with pytest.raises(ValueError, match="checkpoint requires a valid head"):
        audit.reconcile(str(tmp_path), 3, head)
    assert (tmp_path / "audit.log").read_bytes() == original


def test_empty_checkpoint_rejects_nonempty_head(tmp_path, monkeypatch):
    original = _legacy_log(tmp_path)
    _, head = audit.head(str(tmp_path))
    monkeypatch.setattr(
        audit,
        "truncate",
        lambda *_args: pytest.fail("incoherent checkpoint must not truncate"),
    )
    with pytest.raises(ValueError, match="empty audit checkpoint"):
        audit.reconcile(str(tmp_path), 0, head)
    assert (tmp_path / "audit.log").read_bytes() == original


def test_explicit_empty_checkpoint_still_dispatches_orphan_recovery(
    tmp_path, monkeypatch
):
    _legacy_log(tmp_path, count=1)
    calls = []
    monkeypatch.setattr(
        audit, "truncate", lambda root, keep: calls.append((root, keep))
    )
    assert audit.reconcile(str(tmp_path), 0, None) == 1
    assert calls == [(str(tmp_path), 0)]


@pytest.mark.parametrize("count", [None, False, -1, 3])
def test_cli_refuses_unknown_or_incomplete_checkpoint_without_writes(tmp_path, count):
    original = _legacy_log(tmp_path)
    data = _repo().data
    data["manifest"].update(auditSeq=count, auditHead=None)
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    before = path.read_bytes()
    result = CliRunner().invoke(main, ["recover", "--root", str(tmp_path)])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert isinstance(result.exception, SystemExit)
    assert (
        "no auditSeq anchor" in result.output
        if count is None
        else "checkpoint" in result.output
    )
    assert (tmp_path / "audit.log").read_bytes() == original
    assert path.read_bytes() == before


def test_service_does_not_coerce_boolean_checkpoint_to_zero(tmp_path, monkeypatch):
    original = _legacy_log(tmp_path)
    repo = _repo()
    repo.data["manifest"]["auditSeq"] = False
    monkeypatch.setattr(
        audit,
        "truncate",
        lambda *_args: pytest.fail("invalid checkpoint must not truncate"),
    )
    with pytest.raises(DocumentError, match="checkpoint count"):
        _service(tmp_path)._reconcile_audit(repo)
    assert (tmp_path / "audit.log").read_bytes() == original
