"""Native legacy adoption: authorization, byte preservation and crash retry."""

import copy
import hashlib
import json
import os
from contextlib import contextmanager
from datetime import timedelta

import coincurve
import pytest
import yaml
from click.testing import CliRunner

from phantomdocs import audit, audit_baseline, cli, documents, signing
from phantomdocs.audit_baseline import (
    baseline_issues,
    checkpoint_plan,
    prepare_signing_request,
    read_checkpoint_plan,
    signing_request,
)
from phantomdocs.cli import main
from phantomdocs.documents import DocumentError, DocumentService
from phantomdocs.identity import doc_version_mac_from_hash, root_mac
from phantomdocs.manifest import empty_manifest, load

posix = pytest.mark.skipif(
    os.name == "nt", reason="Native durable writes require POSIX fsync/mode semantics"
)


@pytest.fixture
def legacy(tmp_path):
    tmp_path.chmod(0o700)
    secret = coincurve.PrivateKey().secret.hex()
    worker_secret = coincurve.PrivateKey().secret.hex()
    org = {
        "version": 1,
        "organization": {"id": "sample-org"},
        "policies": {
            "security_categories": {"category-2": {}},
            "access_levels": {"operator": {"categories": [2]}},
        },
        "roles": [
            {"id": "administrator", "reports_to": None, "access_level": "operator"},
            {"id": "worker", "reports_to": "administrator", "access_level": "operator"},
        ],
        "actors": [
            {
                "id": "custodian",
                "role": "administrator",
                "npub": signing.npub_encode(signing.pubkey_from_nsec(secret)),
            },
            {
                "id": "worker",
                "role": "worker",
                "npub": signing.npub_encode(signing.pubkey_from_nsec(worker_secret)),
            },
        ],
    }
    policy = tmp_path / "org.yaml"
    policy.write_text(yaml.safe_dump(org), encoding="utf-8")
    key = tmp_path / "key.txt"
    key.write_text(secret, encoding="utf-8")
    key.chmod(0o600)
    data = empty_manifest("sample-org", "docs", root_mac("sample-org", "", "docs"))
    for field in ("auditSeq", "auditHead", "headSeq", "headMac"):
        data["manifest"].pop(field)
    content = b"Fictional legacy document"
    digest = hashlib.sha256(content).hexdigest()
    blob = tmp_path / "blobs" / digest[:2] / digest
    blob.parent.mkdir(parents=True)
    blob.write_bytes(content)
    mac = doc_version_mac_from_hash(
        data["manifest"]["rootMac"], None, "legacy.txt", digest
    )
    urn = "urn:sample-org:doc:legacy.txt"
    data["nodes"] = [
        {
            "urn": urn,
            "mac": mac,
            "parentMac": data["manifest"]["rootMac"],
            "kind": "doc",
            "slug": "legacy.txt",
            "category": "category-2",
            "contentHash": digest,
            "size": len(content),
            "owners": ["administrator"],
            "locations": [{"backend": "local", "path": str(blob)}],
            "meta": {},
            "relations": {},
            "previous": None,
        }
    ]
    data["currentVersions"][urn] = mac
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(yaml.safe_dump(data), encoding="utf-8")
    for _index in range(3):
        audit.append(str(tmp_path), "custodian", "add", urn, mac, digest)
    plan = checkpoint_plan(str(tmp_path), data, org, "custodian")
    return {
        "root": tmp_path,
        "policy": policy,
        "key": key,
        "org": org,
        "data": data,
        "manifest": manifest,
        "plan": plan,
        "blob": blob,
        "audit_before": (tmp_path / "audit.log").read_bytes(),
        "manifest_before": manifest.read_bytes(),
    }


def _service(case, *, key=True):
    return DocumentService(
        str(case["root"]),
        str(case["policy"]),
        "custodian",
        str(case["key"]) if key else None,
    )


def _apply(case, service=None, plan=None, reason="Reviewed legacy history"):
    return (service or _service(case)).adopt_audit_checkpoint(
        plan=plan if plan is not None else case["plan"], reason=reason
    )


def test_plan_is_read_only_and_marks_unsigned_history(legacy):
    case = legacy
    before = copy.deepcopy(case["data"])
    plan = checkpoint_plan(str(case["root"]), case["data"], case["org"], "custodian")
    assert plan["audit_count"] == 3
    assert plan["node_count"] == plan["unsigned_nodes"] == 1
    assert plan["next_seq"] == 1
    assert plan["audit_digest"] == hashlib.sha256(case["audit_before"]).hexdigest()
    assert case["data"] == before
    assert case["manifest"].read_bytes() == case["manifest_before"]
    assert (case["root"] / "audit.log").read_bytes() == case["audit_before"]
    assert not (case["root"] / "manifest.lock").exists()


def test_non_admin_cannot_plan(legacy):
    with pytest.raises(ValueError, match="namespace administrator"):
        checkpoint_plan(str(legacy["root"]), legacy["data"], legacy["org"], "worker")


@pytest.mark.parametrize(
    "field,value",
    [
        ("auditSeq", 0),
        ("auditHead", "a" * 64),
        ("signedRootMac", "signed"),
        ("sealPubkey", "a" * 64),
    ],
)
def test_partial_or_sealed_namespaces_need_separate_review(legacy, field, value):
    data = copy.deepcopy(legacy["data"])
    data["manifest"][field] = value
    with pytest.raises(ValueError):
        checkpoint_plan(str(legacy["root"]), data, legacy["org"], "custodian")


def test_org_namespace_mismatch_is_refused(legacy):
    org = copy.deepcopy(legacy["org"])
    org["organization"]["id"] = "another-org"
    with pytest.raises(ValueError, match="identity does not match"):
        checkpoint_plan(str(legacy["root"]), legacy["data"], org, "custodian")


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("version", 1.0),
        ("cryptoVersion", True),
        ("cryptoVersion", 1.0),
        ("cryptoVersion", 2),
    ],
)
def test_unknown_or_noninteger_namespace_versions_are_refused(legacy, field, value):
    data = copy.deepcopy(legacy["data"])
    data["manifest"][field] = value
    with pytest.raises(ValueError, match="version|structure"):
        checkpoint_plan(str(legacy["root"]), data, legacy["org"], "custodian")


def test_uncanonical_snapshot_metadata_is_a_clean_validation_error(legacy):
    data = copy.deepcopy(legacy["data"])
    data["nodes"][0]["meta"]["unsupported"] = {"set-value"}
    with pytest.raises(ValueError, match="canonical JSON values"):
        checkpoint_plan(str(legacy["root"]), data, legacy["org"], "custodian")


def test_baseline_verifier_refuses_nonmapping_direct_input(legacy):
    for invalid in [None, [], {}, {"manifest": None}]:
        assert baseline_issues(str(legacy["root"]), invalid)


def test_signer_must_be_valid_at_the_exact_recorded_timestamp(legacy, monkeypatch):
    org = copy.deepcopy(legacy["org"])
    actor = org["actors"][0]
    actor["keys"] = [{"npub": actor["npub"], "valid_until": "9998-01-01T00:00:00Z"}]
    legacy["policy"].write_text(yaml.safe_dump(org), encoding="utf-8")
    plan = checkpoint_plan(str(legacy["root"]), legacy["data"], org, "custodian")
    monkeypatch.setattr(audit_baseline, "_now_iso", lambda: "9999-01-01T00:00:00Z")
    with pytest.raises(DocumentError, match="adoption timestamp"):
        _apply(legacy, plan=plan)
    assert legacy["manifest"].read_bytes() == legacy["manifest_before"]
    assert (legacy["root"] / "audit.log").read_bytes() == legacy["audit_before"]


@pytest.mark.parametrize("suffix", [b'{"broken":', b"\n", b"[]\n"])
def test_incomplete_or_ambiguous_audit_is_preserved(legacy, suffix):
    path = legacy["root"] / "audit.log"
    path.write_bytes(legacy["audit_before"] + suffix)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        checkpoint_plan(str(legacy["root"]), legacy["data"], legacy["org"], "custodian")
    assert path.read_bytes() == before


def test_plan_parser_refuses_duplicates_large_input_and_boolean_counts(legacy):
    path = legacy["root"] / "review.json"
    path.write_text('{"schema": "first", "schema": "second"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_checkpoint_plan(str(path))
    path.write_bytes(b" " * 65537)
    with pytest.raises(ValueError, match="64 KiB"):
        read_checkpoint_plan(str(path))
    plan = copy.deepcopy(legacy["plan"])
    plan["next_seq"] = True
    path.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(ValueError, match="next_seq"):
        read_checkpoint_plan(str(path))


def test_cli_prints_only_a_private_plan_without_writes(legacy):
    case = legacy
    result = CliRunner().invoke(
        main,
        [
            "audit-checkpoint-plan",
            "--org-yaml",
            str(case["policy"]),
            "--actor",
            "custodian",
            "--root",
            str(case["root"]),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == case["plan"]
    assert case["manifest"].read_bytes() == case["manifest_before"]
    assert (case["root"] / "audit.log").read_bytes() == case["audit_before"]


def _signed_snapshot(case, *, signing_secret=None):
    """Build detached proof fixtures; not a substitute for transaction tests."""
    payload = {
        "version": 1,
        "action": "adopt-audit-checkpoint",
        "plan": case["plan"],
        "reason": "Reviewed legacy history",
        "issued_at": "2026-01-02T03:04:05Z",
        "seq": case["plan"]["next_seq"],
    }
    envelope = audit_baseline._envelope(payload)
    secret = signing_secret or case["key"].read_text(encoding="utf-8")
    record = {
        "payload": payload,
        "sig": signing.sign_mutation(secret, envelope),
        "sigPubkey": signing.pubkey_from_nsec(secret),
    }
    audit.append(
        str(case["root"]),
        "custodian",
        "adopt-audit-checkpoint",
        "urn:sample-org:namespace:docs",
        hashlib.sha256(envelope).hexdigest(),
        None,
        record["sig"],
        record["sigPubkey"],
        seq=payload["seq"],
        details=record,
        timestamp=payload["issued_at"],
    )
    count, head = audit.head(str(case["root"]))
    data = copy.deepcopy(case["data"])
    data["manifest"].update(
        auditBaseline=record,
        auditSeq=count,
        auditHead=head,
        headSeq=payload["seq"],
        headMac=case["plan"]["structural_head"],
    )
    return data


def test_baseline_evidence_checks_key_binding_and_namespace(legacy):
    data = _signed_snapshot(legacy, signing_secret=coincurve.PrivateKey().secret.hex())
    problems = baseline_issues(
        str(legacy["root"]), data, legacy["org"], require_org=True
    )
    assert "declared valid actor key" in "; ".join(problems)


@pytest.mark.parametrize("field,value", [("sig", "0" * 128), ("sigPubkey", "0" * 64)])
def test_signature_tampering_is_refused(legacy, field, value):
    data = _signed_snapshot(legacy)
    data["manifest"]["auditBaseline"][field] = value
    assert baseline_issues(str(legacy["root"]), data, legacy["org"])


def test_historical_key_rotation_uses_the_adoption_timestamp(legacy):
    data = _signed_snapshot(legacy)
    org = copy.deepcopy(legacy["org"])
    actor = org["actors"][0]
    old = actor["npub"]
    actor["npub"] = signing.npub_encode(
        coincurve.PrivateKey().public_key.format()[1:].hex()
    )
    actor["keys"] = [{"npub": old, "valid_until": "2026-02-01T00:00:00Z"}]
    assert baseline_issues(str(legacy["root"]), data, org, require_org=True) == []
    actor["keys"][0]["revoked_at"] = "2026-01-01T00:00:00Z"
    assert "declared valid actor key" in "; ".join(
        baseline_issues(str(legacy["root"]), data, org)
    )


def test_prefix_deletion_or_receipt_removal_is_detected(legacy):
    data = _signed_snapshot(legacy)
    data["manifest"].pop("auditBaseline")
    assert "receipt is missing" in "; ".join(
        baseline_issues(str(legacy["root"]), data, legacy["org"])
    )
    path = legacy["root"] / "audit.log"
    path.write_bytes(path.read_bytes().split(b"\n", 1)[1])
    assert baseline_issues(str(legacy["root"]), data, legacy["org"])


def test_short_append_is_an_error_and_preserves_the_legacy_prefix(legacy, monkeypatch):
    original_open = open

    class ShortWrite:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, content):
            self.stream.write(content[:7])
            return 7

    def short_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        return ShortWrite(stream) if mode == "ab" else stream

    monkeypatch.setattr(audit, "open", short_open, raising=False)
    with pytest.raises(OSError, match="incomplete audit append"):
        audit.append(
            str(legacy["root"]), "custodian", "example", "urn:sample", "a" * 64, None
        )
    raw = (legacy["root"] / "audit.log").read_bytes()
    assert raw.startswith(legacy["audit_before"])
    assert len(raw) == len(legacy["audit_before"]) + 7


def test_manual_recovery_loads_and_reconciles_under_the_writer_lock(
    legacy, monkeypatch
):
    data = _signed_snapshot(legacy)
    legacy["manifest"].write_text(yaml.safe_dump(data), encoding="utf-8")
    held = []
    original_load, original_reconcile = cli._load_or_die, cli.audit_reconcile

    @contextmanager
    def lock(_path):
        held.append(True)
        try:
            yield
        finally:
            held.pop()

    def locked_load(root):
        assert held
        return original_load(root)

    def locked_reconcile(*args):
        assert held
        return original_reconcile(*args)

    monkeypatch.setattr(cli, "manifest_lock", lock)
    monkeypatch.setattr(cli, "_load_or_die", locked_load)
    monkeypatch.setattr(cli, "audit_reconcile", locked_reconcile)
    result = CliRunner().invoke(main, ["recover", "--root", str(legacy["root"])])
    assert result.exit_code == 0, result.output
    assert not held


@posix
def test_adoption_preserves_every_old_byte_node_reference_and_original(
    legacy, monkeypatch
):
    case = legacy
    monkeypatch.setattr(
        audit, "truncate", lambda *_args: pytest.fail("adoption must never truncate")
    )
    result = _apply(case)
    data = load(str(case["manifest"]))
    raw = (case["root"] / "audit.log").read_bytes()
    assert result == {
        "unchanged": False,
        "resumed": False,
        "seq": 1,
        "preserved_entries": 3,
    }
    assert raw.startswith(case["audit_before"])
    assert len(raw.splitlines()) == 4
    for field in ("nodes", "refs", "currentVersions"):
        assert data[field] == case["data"][field]
    assert case["blob"].read_bytes() == b"Fictional legacy document"
    assert data["manifest"]["auditSeq"] == 4
    assert data["manifest"]["headSeq"] == 1
    assert baseline_issues(str(case["root"]), data, case["org"], require_org=True) == []
    assert not data["nodes"][0].get("sig")  # No invented historical signature.
    before = raw, case["manifest"].read_bytes()
    assert _apply(case)["unchanged"] is True
    assert (
        (case["root"] / "audit.log").read_bytes(),
        case["manifest"].read_bytes(),
    ) == before


@posix
def test_missing_key_and_changed_authority_refuse_without_data_writes(legacy):
    case = legacy
    with pytest.raises(DocumentError, match="signing key"):
        _apply(case, _service(case, key=False))
    service = _service(case)
    org = copy.deepcopy(case["org"])
    org["roles"][0]["reports_to"] = "another-root"
    org["roles"].append({"id": "another-root", "reports_to": None})
    case["policy"].write_text(yaml.safe_dump(org), encoding="utf-8")
    with pytest.raises(DocumentError, match="namespace administrator"):
        _apply(case, service)
    assert case["manifest"].read_bytes() == case["manifest_before"]
    assert (case["root"] / "audit.log").read_bytes() == case["audit_before"]


@posix
def test_durable_entry_uses_the_exact_signed_timestamp(legacy, monkeypatch):
    monkeypatch.setattr(audit_baseline, "_now_iso", lambda: "2026-01-02T03:04:05Z")
    _apply(legacy)
    entry = json.loads((legacy["root"] / "audit.log").read_bytes().splitlines()[-1])
    assert (
        entry["ts"]
        == entry["details"]["payload"]["issued_at"]
        == "2026-01-02T03:04:05Z"
    )
    assert (
        baseline_issues(
            str(legacy["root"]), load(str(legacy["manifest"])), legacy["org"]
        )
        == []
    )


@posix
@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_digest", "1" * 64),
        ("audit_head", "2" * 64),
        ("audit_digest", "3" * 64),
        ("policy_hash", "4" * 64),
        ("next_seq", True),
        ("actor", "worker"),
    ],
)
def test_stale_or_forged_plan_cannot_change_data(legacy, field, value):
    plan = copy.deepcopy(legacy["plan"])
    plan[field] = value
    with pytest.raises(DocumentError):
        _apply(legacy, plan=plan)
    assert legacy["manifest"].read_bytes() == legacy["manifest_before"]
    assert (legacy["root"] / "audit.log").read_bytes() == legacy["audit_before"]


@posix
def test_manifest_failure_retries_durable_signed_tail_without_duplicate(
    legacy, monkeypatch
):
    case = legacy
    original_save = documents.save
    monkeypatch.setattr(
        documents,
        "save",
        lambda *_args: (_ for _ in ()).throw(OSError("synthetic save failure")),
    )
    with pytest.raises(DocumentError, match="interrupted"):
        _apply(case)
    pending = (case["root"] / "audit.log").read_bytes()
    assert pending.startswith(case["audit_before"]) and len(pending.splitlines()) == 4
    assert case["manifest"].read_bytes() == case["manifest_before"]
    with pytest.raises(DocumentError, match="not committed"):
        _service(case)._load_repo()
    assert (case["root"] / "audit.log").read_bytes() == pending
    recover = CliRunner().invoke(main, ["recover", "--root", str(case["root"])])
    assert recover.exit_code != 0 and "no auditSeq anchor" in recover.output
    assert (case["root"] / "audit.log").read_bytes() == pending
    monkeypatch.setattr(documents, "save", original_save)
    result = _apply(case)
    assert result["resumed"] is True
    assert (case["root"] / "audit.log").read_bytes() == pending


@posix
def test_failure_after_manifest_commit_is_idempotent(legacy, monkeypatch):
    original_save = documents.save

    def committed_then_failed(*args):
        original_save(*args)
        raise OSError("synthetic client failure after commit")

    monkeypatch.setattr(documents, "save", committed_then_failed)
    with pytest.raises(DocumentError):
        _apply(legacy)
    before = (legacy["root"] / "audit.log").read_bytes()
    monkeypatch.setattr(documents, "save", original_save)
    assert _apply(legacy)["unchanged"] is True
    assert (legacy["root"] / "audit.log").read_bytes() == before


@posix
def test_failure_before_audit_append_leaves_no_adoption_tail(legacy, monkeypatch):
    original_append = documents.audit_append
    monkeypatch.setattr(
        documents,
        "audit_append",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("synthetic pre-append failure")
        ),
    )
    with pytest.raises(DocumentError):
        _apply(legacy)
    assert legacy["manifest"].read_bytes() == legacy["manifest_before"]
    assert (legacy["root"] / "audit.log").read_bytes() == legacy["audit_before"]
    monkeypatch.setattr(documents, "audit_append", original_append)
    assert _apply(legacy)["resumed"] is False
    assert len((legacy["root"] / "audit.log").read_bytes().splitlines()) == 4


@posix
def test_normal_orphan_recovery_after_adoption_preserves_the_baseline(legacy):
    _apply(legacy)
    committed = (legacy["root"] / "audit.log").read_bytes()
    audit.append(
        str(legacy["root"]),
        "custodian",
        "add",
        "urn:sample-org:doc:orphan.txt",
        "1" * 64,
        None,
        seq=2,
    )
    result = CliRunner().invoke(main, ["recover", "--root", str(legacy["root"])])
    assert result.exit_code == 0, result.output
    assert "discarded 1 orphaned audit entry" in result.output
    assert (legacy["root"] / "audit.log").read_bytes() == committed
    assert (
        baseline_issues(
            str(legacy["root"]), load(str(legacy["manifest"])), legacy["org"]
        )
        == []
    )


@posix
def test_unknown_tail_after_pending_adoption_is_never_discarded(legacy, monkeypatch):
    original_save = documents.save
    monkeypatch.setattr(
        documents,
        "save",
        lambda *_args: (_ for _ in ()).throw(OSError("synthetic failure")),
    )
    with pytest.raises(DocumentError):
        _apply(legacy)
    monkeypatch.setattr(documents, "save", original_save)
    audit.append(
        str(legacy["root"]),
        "custodian",
        "unexpected",
        "urn:sample-org:doc:unexpected.txt",
        "2" * 64,
        None,
        seq=2,
    )
    before = (legacy["root"] / "audit.log").read_bytes()
    with pytest.raises(DocumentError, match="pending"):
        _apply(legacy)
    assert (legacy["root"] / "audit.log").read_bytes() == before
    assert legacy["manifest"].read_bytes() == legacy["manifest_before"]


@posix
def test_torn_append_is_preserved_and_requires_separate_review(legacy, monkeypatch):
    path = legacy["root"] / "audit.log"

    def torn(*_args, **_kwargs):
        with path.open("ab") as stream:
            stream.write(b'{"incomplete":')
        raise OSError("synthetic torn append")

    original_append = documents.audit_append
    monkeypatch.setattr(documents, "audit_append", torn)
    with pytest.raises(DocumentError):
        _apply(legacy)
    before = path.read_bytes()
    assert before.startswith(legacy["audit_before"])
    monkeypatch.setattr(documents, "audit_append", original_append)
    with pytest.raises(DocumentError, match="incomplete"):
        _apply(legacy)
    assert path.read_bytes() == before
    assert legacy["manifest"].read_bytes() == legacy["manifest_before"]


@posix
def test_pending_adoption_refuses_changed_reason_or_policy(legacy, monkeypatch):
    original_save = documents.save
    monkeypatch.setattr(
        documents,
        "save",
        lambda *_args: (_ for _ in ()).throw(OSError("synthetic failure")),
    )
    with pytest.raises(DocumentError):
        _apply(legacy)
    before = (legacy["root"] / "audit.log").read_bytes()
    monkeypatch.setattr(documents, "save", original_save)
    with pytest.raises(DocumentError, match="does not match"):
        _apply(legacy, reason="A different decision")
    org = copy.deepcopy(legacy["org"])
    org["organization"]["label"] = "Updated policy"
    legacy["policy"].write_text(yaml.safe_dump(org), encoding="utf-8")
    with pytest.raises(DocumentError, match="stale"):
        _apply(legacy)
    assert (legacy["root"] / "audit.log").read_bytes() == before


@posix
def test_verification_requires_org_and_detects_receipt_removal(legacy):
    _apply(legacy)
    data = load(str(legacy["manifest"]))
    assert "requires --org-yaml" in "; ".join(
        baseline_issues(str(legacy["root"]), data, require_org=True)
    )
    result = CliRunner().invoke(
        main,
        ["verify", "--root", str(legacy["root"]), "--org-yaml", str(legacy["policy"])],
    )
    assert result.exit_code == 0, result.output
    data["manifest"].pop("auditBaseline")
    assert "receipt is missing" in "; ".join(
        baseline_issues(str(legacy["root"]), data, legacy["org"])
    )


@posix
def test_existing_normal_mutations_work_after_adoption(legacy):
    _apply(legacy)
    service = _service(legacy)
    result = service.add_document(
        content=b"New fictional document",
        ref_location=None,
        slug="new.txt",
        category="category-2",
        folder=None,
        owners=["administrator"],
        backend=None,
    )
    assert result["verb"] == "added"
    assert (
        (legacy["root"] / "audit.log").read_bytes().startswith(legacy["audit_before"])
    )
    assert audit.max_seq(str(legacy["root"])) == 2
    verify = CliRunner().invoke(
        main,
        ["verify", "--root", str(legacy["root"]), "--org-yaml", str(legacy["policy"])],
    )
    assert verify.exit_code == 0, verify.output


@posix
def test_cli_adopts_the_reviewed_plan(legacy):
    path = legacy["root"] / "review.json"
    path.write_text(json.dumps(legacy["plan"]), encoding="utf-8")
    result = CliRunner().invoke(
        main,
        [
            "adopt-audit-checkpoint",
            "--plan",
            str(path),
            "--reason",
            "Reviewed legacy history",
            "--org-yaml",
            str(legacy["policy"]),
            "--nsec-file",
            str(legacy["key"]),
            "--actor",
            "custodian",
            "--root",
            str(legacy["root"]),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["preserved_entries"] == 3


def _external_fixture(case, *, stamp=None, secret=None):
    payload = signing_request(
        case["plan"], "Reviewed legacy history", stamp or documents._now_iso()
    )
    secret = secret or case["key"].read_text()
    return {
        "payload": payload,
        "sigPubkey": signing.pubkey_from_nsec(secret),
        "sig": signing.sign_mutation(secret, audit_baseline._envelope(payload)),
    }


def _external_service(case):
    return DocumentService(
        str(case["root"]),
        str(case["policy"]),
        "custodian",
        signing_key_from_environment=False,
    )


def test_signing_request_is_detached_read_only_and_stale_guarded(legacy):
    c = legacy
    request = prepare_signing_request(
        str(c["root"]),
        c["data"],
        c["org"],
        "custodian",
        c["plan"],
        "Reviewed legacy history",
    )
    assert request["action"] == "adopt-audit-checkpoint"
    request["plan"]["actor"] = "other"
    assert c["plan"]["actor"] == "custodian"
    stale = copy.deepcopy(c["plan"])
    stale["audit_digest"] = "a" * 64
    with pytest.raises(ValueError, match="stale"):
        prepare_signing_request(
            str(c["root"]),
            c["data"],
            c["org"],
            "custodian",
            stale,
            "Reviewed legacy history",
        )
    assert c["manifest"].read_bytes() == c["manifest_before"]


def test_external_service_does_not_resolve_environment_key(legacy, monkeypatch):
    monkeypatch.setenv("PHANTOMDOCS_NSEC", "not-a-private-key")
    monkeypatch.setattr(documents, "_signing_key", lambda *_: pytest.fail("key access"))
    assert _external_service(legacy).nsec is None


@pytest.mark.parametrize(
    "change", ["signature", "actor", "reason", "extra", "domain", "key"]
)
def test_external_record_contract_rejects_mismatch(legacy, change):
    c = legacy
    r = _external_fixture(c)
    if change == "signature":
        r["sig"] = "0" * 128
    elif change == "actor":
        r["payload"]["plan"]["actor"] = "worker"
    elif change == "reason":
        r["payload"]["reason"] = "Another reason"
    elif change == "extra":
        r["payload"]["digest"] = "0" * 64
    elif change == "domain":
        r["sig"] = signing.sign_mutation(c["key"].read_text(), b"another-domain")
    else:
        r = _external_fixture(c, secret=coincurve.PrivateKey().secret.hex())
    with pytest.raises(ValueError):
        audit_baseline._external_record(
            r, c["plan"], "Reviewed legacy history", c["org"], "custodian"
        )


@posix
def test_external_adoption_preserves_bytes_without_local_key_and_is_idempotent(
    legacy, monkeypatch
):
    c = legacy
    r = _external_fixture(c)
    service = _external_service(c)
    monkeypatch.setattr(
        audit_baseline, "sign_mutation", lambda *_: pytest.fail("local signing")
    )
    result = service.adopt_audit_checkpoint(
        plan=c["plan"], reason="Reviewed legacy history", signed_record=r
    )
    assert result["preserved_entries"] == 3
    data = load(str(c["manifest"]))
    assert data["manifest"]["auditBaseline"] == r
    assert data["nodes"] == c["data"]["nodes"]
    raw = (c["root"] / "audit.log").read_bytes()
    assert raw.startswith(c["audit_before"]) and len(raw.splitlines()) == 4
    assert service.adopt_audit_checkpoint(
        plan=c["plan"], reason="Reviewed legacy history", signed_record=r
    )["unchanged"]
    assert (c["root"] / "audit.log").read_bytes() == raw


@posix
@pytest.mark.parametrize("stamp", ["2000-01-01T00:00:00Z", "9999-01-01T00:00:00Z"])
def test_external_stale_or_future_signature_never_appends(legacy, stamp):
    c = legacy
    with pytest.raises(DocumentError, match="60 seconds"):
        _external_service(c).adopt_audit_checkpoint(
            plan=c["plan"],
            reason="Reviewed legacy history",
            signed_record=_external_fixture(c, stamp=stamp),
        )
    assert c["manifest"].read_bytes() == c["manifest_before"]
    assert (c["root"] / "audit.log").read_bytes() == c["audit_before"]


@posix
def test_external_pending_retry_keeps_durable_record_after_expiry(legacy, monkeypatch):
    c = legacy
    r = _external_fixture(c)
    service = _external_service(c)
    original_save = documents.save
    monkeypatch.setattr(
        documents,
        "save",
        lambda *_: (_ for _ in ()).throw(OSError("interrupted")),
    )
    with pytest.raises(DocumentError):
        service.adopt_audit_checkpoint(
            plan=c["plan"], reason="Reviewed legacy history", signed_record=r
        )
    monkeypatch.setattr(documents, "save", original_save)
    real_datetime = audit_baseline.datetime

    class Later(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(tz) + timedelta(minutes=2)

    monkeypatch.setattr(audit_baseline, "datetime", Later)
    before = (c["root"] / "audit.log").read_bytes()
    result = service.adopt_audit_checkpoint(
        plan=c["plan"], reason="Reviewed legacy history", signed_record=r
    )
    assert result["resumed"] is True
    assert (c["root"] / "audit.log").read_bytes() == before


def test_request_cli_does_not_access_keys(legacy, monkeypatch):
    c = legacy
    path = c["root"] / "plan.json"
    path.write_text(json.dumps(c["plan"]))
    monkeypatch.setattr(documents, "_signing_key", lambda *_: pytest.fail("key access"))
    out = CliRunner().invoke(
        main,
        [
            "audit-checkpoint-request",
            "--root",
            str(c["root"]),
            "--org-yaml",
            str(c["policy"]),
            "--actor",
            "custodian",
            "--plan",
            str(path),
            "--reason",
            "Reviewed legacy history",
        ],
    )
    assert out.exit_code == 0, out.output
    assert json.loads(out.output)["plan"] == c["plan"]


@posix
def test_external_cli_ignores_environment_key_and_preserves_originals(
    legacy, monkeypatch
):
    c = legacy
    record = _external_fixture(c)
    rp, pp = c["root"] / "record.json", c["root"] / "plan.json"
    rp.write_text(json.dumps(record))
    pp.write_text(json.dumps(c["plan"]))
    monkeypatch.setenv("PHANTOMDOCS_NSEC", "invalid-secret-must-not-be-read")
    monkeypatch.setattr(documents, "_signing_key", lambda *_: pytest.fail("key access"))
    args = [
        "adopt-audit-checkpoint",
        "--root",
        str(c["root"]),
        "--org-yaml",
        str(c["policy"]),
        "--actor",
        "custodian",
        "--plan",
        str(pp),
        "--reason",
        "Reviewed legacy history",
        "--signed-record",
        str(rp),
    ]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["preserved_entries"] == 3
    assert c["blob"].read_bytes() == b"Fictional legacy document"


@posix
@pytest.mark.parametrize("change", ["policy", "manifest", "authority", "reason", "key"])
def test_external_apply_rechecks_authority_and_entire_snapshot(legacy, change):
    c = legacy
    record = _external_fixture(c)
    service = _external_service(c)
    reason = "Reviewed legacy history"
    if change in ("policy", "authority", "key"):
        org = copy.deepcopy(c["org"])
        if change == "policy":
            org["organization"]["name"] = "New policy snapshot"
        elif change == "authority":
            org["actors"][0]["role"] = "worker"
        else:
            org["actors"][0]["npub"] = signing.npub_encode(
                signing.pubkey_from_nsec(coincurve.PrivateKey().secret.hex())
            )
        c["policy"].write_text(yaml.safe_dump(org))
    elif change == "manifest":
        data = copy.deepcopy(c["data"])
        data["nodes"][0]["meta"]["review"] = "changed"
        c["manifest"].write_text(yaml.safe_dump(data))
    else:
        reason = "Different reason"
    before = c["manifest"].read_bytes()
    with pytest.raises(DocumentError):
        service.adopt_audit_checkpoint(
            plan=c["plan"], reason=reason, signed_record=record
        )
    assert c["manifest"].read_bytes() == before
    assert (c["root"] / "audit.log").read_bytes() == c["audit_before"]


def test_external_reader_refuses_ambiguous_or_oversized_records(legacy):
    path = legacy["root"] / "record.json"
    path.write_text('{"payload":{},"payload":{}}')
    with pytest.raises(ValueError, match="duplicate"):
        audit_baseline.read_signed_checkpoint(str(path))
    path.write_bytes(b" " * 65537)
    with pytest.raises(ValueError, match="64 KiB"):
        audit_baseline.read_signed_checkpoint(str(path))
    record = _external_fixture(legacy)
    path.write_text(json.dumps(record))
    assert audit_baseline.read_signed_checkpoint(str(path)) == record
