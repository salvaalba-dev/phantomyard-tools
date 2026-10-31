"""Exercise only synthetic audit histories, never a real installation."""

import copy
import json
import multiprocessing
import os
from contextlib import contextmanager, nullcontext

import pytest
import test_local_classification as fixtures
import test_workflow_reconcile as verification_fixtures
import yaml
from click.testing import CliRunner

from phantomdocs import audit, cli, manifest
from phantomdocs import workflow_provenance_audit as provenance_audit
from phantomdocs.identity import doc_version_mac_from_hash
from phantomdocs.workflow_provenance_audit import apply, links_for_scan, review


@pytest.fixture
def case(tmp_path, monkeypatch):
    if os.name == "nt":
        # Logic-only coverage; locking and durability must be tested on POSIX.
        monkeypatch.setattr(manifest, "preserve_mode", lambda *args: None)
        monkeypatch.setattr(manifest, "manifest_lock", lambda *args: nullcontext())
    result = fixtures.case.__wrapped__(tmp_path)
    org = result["org"]
    org["documents"] = {"inboxes": {"custodian": {"id": "shared-intake"}}}
    result["policy"].write_text(yaml.safe_dump(org), encoding="utf-8")
    data = manifest.load(str(result["path"]))
    node = manifest.node_by_urn(data, result["intent"]["ref"])
    node["locations"] = [{"backend": "gdrive", "ref": "archive-id"}]
    manifest.save(str(result["path"]), data)
    result["current"] = node
    receipt_dir = tmp_path / "reviewed-receipts"
    receipt_dir.mkdir(mode=0o700)
    receipt_dir.chmod(0o700)
    result["receipt_dir"] = receipt_dir
    if os.name == "nt":
        monkeypatch.setattr(
            provenance_audit, "trusted_receipt_directory", lambda _path: nullcontext(-1)
        )
        monkeypatch.setattr(
            provenance_audit,
            "read_receipt",
            lambda _fd, name: json.loads(
                (receipt_dir / name).read_text(encoding="utf-8")
            ),
        )
    return result


def plan(case):
    node = case["current"]
    return review(
        str(case["root"]),
        str(case["policy"]),
        "custodian",
        inbox_name="custodian",
        urn=node["urn"],
        inbox_ref="gdrive://inbox-copy",
        archive_ref="gdrive://archive-id",
        sha256=node["contentHash"],
    )


class Reader(verification_fixtures.FakeReader):
    def metadata(self, ref):
        value = super().metadata(ref)
        value["id"] = "inbox-copy"
        return value

    def read_reference(self, ref, *, streaming):
        snapshot, _ = super().read_reference(ref, streaming=streaming)
        return snapshot, {"backend": "gdrive", "ref": "inbox-copy"}


def execute(case, proposal, reader=None, receipt=None):
    link = proposal["link"]
    if receipt is None:
        receipt = {
            "inbox_ref": link["inbox_ref"],
            "archive_ref": link["archive_ref"],
            "sha256": link["content_sha256"],
        }
    receipt_path = case["receipt_dir"] / "reviewed.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    receipt_path.chmod(0o600)
    return apply(
        str(case["root"]),
        str(case["policy"]),
        "custodian",
        proposal,
        receipt_directory=str(case["receipt_dir"]),
        receipt_name="reviewed.json",
        inbox_name="custodian",
        reader=reader or Reader(b"Second fictional version"),
    )


def test_apply_and_repeat_add_exactly_one_audit_entry(case):
    proposal = plan(case)
    nodes = copy.deepcopy(manifest.load(str(case["path"]))["nodes"])
    before, _ = audit.head(str(case["root"]))
    assert execute(case, proposal)["unchanged"] is False
    assert execute(case, proposal)["unchanged"] is True
    assert audit.head(str(case["root"]))[0] == before + 1
    stored = manifest.load(str(case["path"]))
    assert stored["nodes"] == nodes
    assert audit.verify_chain(str(case["root"])) == []
    assert audit.sequence_issues(str(case["root"])) == []
    assert manifest.structural_issues(stored) == []
    assert manifest.mutation_sequence_issues(stored) == []
    entry = json.loads((case["root"] / "audit.log").read_bytes().splitlines()[-1])
    assert entry["details"]["trust_mode"] == "trusted-local-process"
    assert len(entry["details"]["receipt_claims_digest"]) == 64
    assert entry["details"]["operator_uid"] == (
        os.geteuid() if hasattr(os, "geteuid") else None
    )


def test_failed_verification_writes_nothing(case):
    proposal = plan(case)
    before = (case["path"].read_bytes(), (case["root"] / "audit.log").read_bytes())
    with pytest.raises(ValueError, match="not verified"):
        execute(case, proposal, reader=Reader(b"changed content"))
    assert (
        case["path"].read_bytes(),
        (case["root"] / "audit.log").read_bytes(),
    ) == before


def test_mismatched_delivery_record_writes_nothing(case):
    proposal = plan(case)
    previous = (case["root"] / "audit.log").read_bytes()
    with pytest.raises(ValueError, match="receipt differs"):
        execute(
            case,
            proposal,
            receipt={
                "inbox_ref": "gdrive://other",
                "archive_ref": "gdrive://archive-id",
                "sha256": proposal["link"]["content_sha256"],
            },
        )
    assert (case["root"] / "audit.log").read_bytes() == previous


def test_changed_drive_metadata_writes_nothing(case):
    proposal = plan(case)
    before = (case["path"].read_bytes(), (case["root"] / "audit.log").read_bytes())
    with pytest.raises(ValueError, match="not verified"):
        execute(case, proposal, reader=Reader(b"Second fictional version", change=True))
    assert (
        case["path"].read_bytes(),
        (case["root"] / "audit.log").read_bytes(),
    ) == before


def test_download_does_not_hold_manifest_lock(case, monkeypatch):
    proposal = plan(case)
    lock = manifest.manifest_lock
    held = {"value": False}

    @contextmanager
    def tracked(path):
        with lock(path):
            held["value"] = True
            try:
                yield
            finally:
                held["value"] = False

    class CheckingReader(Reader):
        def read_reference(self, ref, *, streaming):
            assert held["value"] is False
            return super().read_reference(ref, streaming=streaming)

    monkeypatch.setattr(manifest, "manifest_lock", tracked)
    assert (
        execute(case, proposal, reader=CheckingReader(b"Second fictional version"))[
            "unchanged"
        ]
        is False
    )


def test_audit_change_during_download_refuses_to_append(case):
    proposal = plan(case)

    class ChangingReader(Reader):
        def read_reference(self, ref, *, streaming):
            audit.append(
                str(case["root"]),
                "custodian",
                "other",
                case["current"]["urn"],
                case["current"]["mac"],
                None,
                seq=proposal["next_seq"],
            )
            return super().read_reference(ref, streaming=streaming)

    with pytest.raises(ValueError, match="stale or unknown audit tail"):
        execute(case, proposal, reader=ChangingReader(b"Second fictional version"))
    rows = [
        json.loads(line)
        for line in (case["root"] / "audit.log").read_bytes().splitlines()
    ]
    assert rows[-1]["action"] == "other"


def test_provider_change_after_download_is_rejected(case):
    proposal = plan(case)
    before = (case["root"] / "audit.log").read_bytes()

    class ChangingReader(Reader):
        def metadata(self, ref):
            result = super().metadata(ref)
            if self.calls >= 3:
                result["version"] = "2"
            return result

    with pytest.raises(ValueError, match="metadata changed"):
        execute(case, proposal, reader=ChangingReader(b"Second fictional version"))
    assert (case["root"] / "audit.log").read_bytes() == before


def test_policy_changes_are_rejected(case):
    proposal = plan(case)
    org = yaml.safe_load(case["policy"].read_text(encoding="utf-8"))
    org["policies"]["access_levels"]["both"]["categories"] = [2]
    case["policy"].write_text(yaml.safe_dump(org), encoding="utf-8")
    previous = (case["root"] / "audit.log").read_bytes()
    with pytest.raises(ValueError):
        execute(case, proposal)
    assert (case["root"] / "audit.log").read_bytes() == previous


def test_interrupted_commit_resumes_existing_audit_entry(case, monkeypatch):
    proposal = plan(case)
    save = manifest.save

    def fail(*args, **kwargs):
        raise OSError("simulated failure")

    monkeypatch.setattr(manifest, "save", fail)
    with pytest.raises(OSError, match="simulated"):
        execute(case, proposal)
    count, _ = audit.head(str(case["root"]))
    orphaned = (case["root"] / "audit.log").read_bytes()
    with pytest.raises(ValueError, match="pending intake link"):
        audit.reconcile(
            str(case["root"]), proposal["audit_count"], proposal["audit_head"]
        )
    assert (case["root"] / "audit.log").read_bytes() == orphaned
    monkeypatch.setattr(manifest, "save", save)
    assert execute(case, proposal)["resumed"] is True
    assert audit.head(str(case["root"]))[0] == count


def test_second_plan_for_same_inbox_copy_is_rejected(case):
    execute(case, plan(case))
    with pytest.raises(ValueError, match="already has"):
        plan(case)


def test_recorded_link_is_discoverable_only_for_authorized_reader(case):
    execute(case, plan(case))
    data = manifest.load(str(case["path"]))
    allowed = links_for_scan(str(case["root"]), data, case["org"], "custodian")
    assert allowed["gdrive://inbox-copy"]["node"]["urn"] == case["current"]["urn"]
    hidden = links_for_scan(str(case["root"]), data, case["org"], "unknown")
    assert hidden["gdrive://inbox-copy"] is None


def test_recorded_link_is_held_if_policy_changes(case):
    execute(case, plan(case))
    data = manifest.load(str(case["path"]))
    changed = copy.deepcopy(case["org"])
    changed["organization"]["display_name"] = "Changed policy context"
    result = links_for_scan(str(case["root"]), data, changed, "custodian")
    assert result["gdrive://inbox-copy"] is None


def test_recorded_link_is_held_if_document_version_changes(case):
    execute(case, plan(case))
    data = manifest.load(str(case["path"]))
    node = manifest.node_by_urn(data, case["current"]["urn"])
    newer = copy.deepcopy(node)
    newer["previous"] = node["mac"]
    newer["contentHash"] = "a" * 64
    newer["mac"] = doc_version_mac_from_hash(
        newer["parentMac"], node["mac"], newer["slug"], newer["contentHash"]
    )
    data["nodes"].append(newer)
    data["currentVersions"][node["urn"]] = newer["mac"]
    data["manifest"]["headMac"] = newer["mac"]
    result = links_for_scan(str(case["root"]), data, case["org"], "custodian")
    assert result["gdrive://inbox-copy"] is None


def test_unrelated_history_change_is_never_discarded(case):
    proposal = plan(case)
    audit.append(
        str(case["root"]),
        "custodian",
        "other",
        case["current"]["urn"],
        case["current"]["mac"],
        None,
        seq=proposal["next_seq"],
    )
    previous = (case["root"] / "audit.log").read_bytes()
    with pytest.raises(ValueError, match="unknown audit tail"):
        execute(case, proposal)
    assert (case["root"] / "audit.log").read_bytes() == previous


def test_sealed_history_is_not_modified(case):
    data = manifest.load(str(case["path"]))
    data["manifest"]["requireSignatures"] = True
    manifest.save(str(case["path"]), data)
    before = (case["root"] / "audit.log").read_bytes()
    with pytest.raises(ValueError):
        plan(case)
    assert (case["root"] / "audit.log").read_bytes() == before


def test_cli_review_and_apply_use_separate_reviewed_plan(case, tmp_path, monkeypatch):
    from phantomdocs import workflow_drive_reader

    node = case["current"]
    base = [
        "--root",
        str(case["root"]),
        "--org-yaml",
        str(case["policy"]),
        "--actor",
        "custodian",
    ]
    result = CliRunner().invoke(
        cli.main,
        [
            "workflow",
            "copy-link-review",
            *base,
            "--inbox-name",
            "custodian",
            "--urn",
            node["urn"],
            "--inbox-ref",
            "gdrive://inbox-copy",
            "--archive-ref",
            "gdrive://archive-id",
            "--sha256",
            node["contentHash"],
        ],
    )
    assert result.exit_code == 0, result.output
    proposal = json.loads(result.output)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(proposal), encoding="utf-8")
    receipt = {
        "inbox_ref": "gdrive://inbox-copy",
        "archive_ref": "gdrive://archive-id",
        "sha256": node["contentHash"],
    }
    receipt_path = case["receipt_dir"] / "reviewed.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    receipt_path.chmod(0o600)
    token_path = tmp_path / "token"
    token_path.write_text("synthetic", encoding="utf-8")
    monkeypatch.setattr(
        workflow_drive_reader,
        "DriveArchiveReader",
        lambda *_args, **_kwargs: Reader(b"Second fictional version"),
    )
    result = CliRunner().invoke(
        cli.main,
        [
            "workflow",
            "copy-link-apply",
            *base,
            "--plan",
            str(plan_path),
            "--receipt-directory",
            str(case["receipt_dir"]),
            "--receipt-name",
            "reviewed.json",
            "--drive-token-file",
            str(token_path),
            "--max-bytes",
            "1000",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["unchanged"] is False


def _concurrent_writer(root, org_path, receipt_dir, proposal, start, output):
    start.wait(timeout=10)
    try:
        output.put(
            apply(
                root,
                org_path,
                "custodian",
                proposal,
                receipt_directory=receipt_dir,
                receipt_name="reviewed.json",
                inbox_name="custodian",
                reader=Reader(b"Second fictional version"),
            )
        )
    except (ValueError, OSError) as error:
        output.put({"error": str(error)})


@pytest.mark.skipif(os.name != "posix", reason="Real file locks require POSIX")
def test_concurrent_writers_commit_only_one_link(case):
    proposal = plan(case)
    before, _ = audit.head(str(case["root"]))
    link = proposal["link"]
    receipt_path = case["receipt_dir"] / "reviewed.json"
    receipt_path.write_text(
        json.dumps(
            {
                "inbox_ref": link["inbox_ref"],
                "archive_ref": link["archive_ref"],
                "sha256": link["content_sha256"],
            }
        ),
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    output = context.Queue()
    workers = [
        context.Process(
            target=_concurrent_writer,
            args=(
                str(case["root"]),
                str(case["policy"]),
                str(case["receipt_dir"]),
                proposal,
                barrier,
                output,
            ),
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0
    results = [output.get(timeout=5) for _ in workers]
    assert all("error" not in result for result in results)
    assert sorted(result["unchanged"] for result in results) == [False, True]
    assert audit.head(str(case["root"]))[0] == before + 1
