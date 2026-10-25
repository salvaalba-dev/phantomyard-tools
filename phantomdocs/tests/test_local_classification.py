"""Unsigned classification: exact authority, retained history and crash recovery."""

import copy
import json
import os

import pytest
import test_classification_plan as planning
import yaml
from click.testing import CliRunner

from phantomdocs import audit, cli, documents, manifest
from phantomdocs import local_classification as local
from phantomdocs.identity import doc_version_mac_from_hash

posix = pytest.mark.skipif(
    os.name == "nt", reason="Native fsync/mode checks require POSIX"
)


@pytest.fixture
def case(tmp_path):
    tmp_path.chmod(0o700)
    data, org, intent = planning.model.__wrapped__()
    org["organization"] = {"id": "sample-org"}
    for node, content in zip(
        data["nodes"], (b"First fictional version", b"Second fictional version")
    ):
        path = tmp_path / "blobs" / node["contentHash"][:2] / node["contentHash"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        node["locations"] = [{"backend": "local", "path": str(path)}]
    unrelated = copy.deepcopy(data["nodes"][0])
    unrelated.update(
        urn="urn:sample-org:doc:other.txt", slug="other.txt", previous=None
    )
    unrelated["mac"] = doc_version_mac_from_hash(
        data["manifest"]["rootMac"], None, unrelated["slug"], unrelated["contentHash"]
    )
    data["nodes"].append(unrelated)
    data["currentVersions"][unrelated["urn"]] = unrelated["mac"]
    data["refs"]["retained-v1"] = data["nodes"][0]["mac"]
    for seq, node in enumerate(data["nodes"], 1):
        audit.append(
            str(tmp_path),
            "custodian",
            "add",
            node["urn"],
            node["mac"],
            node["contentHash"],
            seq=seq,
        )
    count, head = audit.head(str(tmp_path))
    data["manifest"].update(
        headSeq=3, headMac=unrelated["mac"], auditSeq=count, auditHead=head
    )
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    path.chmod(0o600)
    policy = tmp_path / "org.yaml"
    policy.write_text(yaml.safe_dump(org), encoding="utf-8")
    policy.chmod(0o600)
    result = {
        "root": tmp_path,
        "path": path,
        "policy": policy,
        "data": data,
        "org": org,
        "intent": intent,
    }
    result["plan"] = _review(result)
    return result


def _review(c, **changes):
    intent = dict(c["intent"], **changes)
    return local.review(str(c["root"]), str(c["policy"]), "custodian", **intent)


def _apply(c, **changes):
    args = {
        "root": str(c["root"]),
        "org_path": str(c["policy"]),
        "actor": "custodian",
        "plan": c["plan"],
    }
    return local.apply(**dict(args, **changes))


def _snapshot(c):
    return (
        c["path"].read_bytes(),
        (c["root"] / "audit.log").read_bytes(),
        c["policy"].read_bytes(),
    )


def _write(c, data):
    c["path"].write_text(yaml.safe_dump(data), encoding="utf-8")


def _invoke(c, command, *args, actor="custodian"):
    return CliRunner().invoke(
        cli.main,
        [
            command,
            *args,
            "--root",
            str(c["root"]),
            "--org-yaml",
            str(c["policy"]),
            "--actor",
            actor,
        ],
    )


def test_review_is_read_only_and_uses_no_signing_key(case, monkeypatch):
    before = _snapshot(case)
    monkeypatch.setattr(documents, "_signing_key", lambda *_: pytest.fail("key access"))
    result = _review(case)
    assert result["schema"] == local.SCHEMA
    assert result["execution_available"] is True
    assert result["mode"] == "unsigned-local-custodian"
    assert result["next_seq"] == 4
    assert len(result["versions"]) == 2
    assert result["reader_impact"]["lost"] == ["organization-reader"]
    assert _snapshot(case) == before
    assert not (case["root"] / "manifest.lock").exists()


@posix
def test_apply_changes_only_category_and_anchors_and_preserves_originals(
    case, monkeypatch
):
    c = case
    before = _snapshot(c)
    originals = {
        p.name: p.read_bytes() for p in (c["root"] / "blobs").rglob("*") if p.is_file()
    }
    monkeypatch.setattr(documents, "_signing_key", lambda *_: pytest.fail("key access"))
    monkeypatch.setattr(audit, "truncate", lambda *_: pytest.fail("audit truncation"))
    monkeypatch.setenv("PHANTOMDOCS_NSEC", "must-not-be-used")
    result = _apply(c)
    assert result == {
        "unchanged": False,
        "resumed": False,
        "signed": False,
        "seq": 4,
        "versions_reclassified": 2,
    }
    changed = manifest.load(str(c["path"]))
    for actual, old in zip(changed["nodes"], c["data"]["nodes"]):
        if old["urn"] == c["intent"]["ref"]:
            assert actual["category"] == "category-4-sample"
            actual["category"] = old["category"]
        assert actual == old
    assert changed["refs"] == c["data"]["refs"]
    assert changed["currentVersions"] == c["data"]["currentVersions"]
    assert changed["manifest"]["headMac"] == c["data"]["manifest"]["headMac"]
    if os.name == "posix":
        assert (c["path"].stat().st_mode & 0o777) == 0o600
    assert originals == {
        p.name: p.read_bytes() for p in (c["root"] / "blobs").rglob("*") if p.is_file()
    }
    raw = (c["root"] / "audit.log").read_bytes()
    assert raw.startswith(before[1]) and len(raw.splitlines()) == 4
    row = json.loads(raw.splitlines()[-1])
    assert row["action"] == local.ACTION and row["details"]["plan"] == c["plan"]
    assert "sig" not in row and "sigPubkey" not in row
    assert audit.verify_chain(str(c["root"])) == []
    assert audit.sequence_issues(str(c["root"])) == []
    assert manifest.structural_issues(changed) == []
    assert manifest.mutation_sequence_issues(changed) == []
    verified = CliRunner().invoke(
        cli.main, ["verify", "--root", str(c["root"]), "--org-yaml", str(c["policy"])]
    )
    assert verified.exit_code == 0, verified.output
    committed = _snapshot(c)
    assert _apply(c) == {"unchanged": True, "signed": False, "seq": 4}
    assert _snapshot(c) == committed


@posix
@pytest.mark.parametrize("selector", ["urn", "mac", "tag"])
def test_old_versions_and_tags_use_new_category_for_every_reader(case, selector):
    c = case
    _apply(c)
    ref = c["intent"]["ref"]
    extra = []
    if selector == "mac":
        extra = ["--mac", c["data"]["nodes"][0]["mac"]]
    elif selector == "tag":
        ref = "retained-v1"
    denied = _invoke(c, "get", ref, *extra, actor="organization-reader")
    allowed = _invoke(c, "get", ref, *extra, actor="project-human")
    assert denied.exit_code != 0 and "denied" in denied.output
    assert allowed.exit_code == 0, allowed.output
    search = _invoke(c, "search", "record", actor="organization-reader")
    assert c["intent"]["ref"] not in search.output
    history = _invoke(c, "versions", ref, actor="project-human")
    assert history.exit_code == 0 and "v2" in history.output
    other = _invoke(c, "get", "other.txt", actor="organization-reader")
    assert other.exit_code == 0
    other_denied = _invoke(c, "get", "other.txt", actor="project-human")
    assert other_denied.exit_code != 0


@posix
def test_next_version_retains_changed_category(case):
    c = case
    _apply(c)
    service = documents.DocumentService(
        str(c["root"]),
        str(c["policy"]),
        "custodian",
        signing_key_from_environment=False,
    )
    service.add_document(
        content=b"Third fictional version",
        ref_location=None,
        slug="record.txt",
        category=None,
        folder=None,
        owners=[],
        backend=None,
    )
    data = manifest.load(str(c["path"]))
    assert {n["category"] for n in manifest.versions_of(data, c["intent"]["ref"])} == {
        "category-4-sample"
    }
    assert len(manifest.versions_of(data, c["intent"]["ref"])) == 3
    with pytest.raises(ValueError):
        _apply(c)


@posix
def test_rollback_retains_changed_category(case):
    c = case
    _apply(c)
    service = documents.DocumentService(
        str(c["root"]),
        str(c["policy"]),
        "custodian",
        signing_key_from_environment=False,
    )
    service.rollback(
        urn=c["intent"]["ref"], to_mac=c["data"]["nodes"][0]["mac"], backend=None
    )
    data = manifest.load(str(c["path"]))
    assert {n["category"] for n in manifest.versions_of(data, c["intent"]["ref"])} == {
        "category-4-sample"
    }


@pytest.mark.parametrize(
    "kind", ["node", "ref", "audit", "required", "seal", "baseline", "historical-seal"]
)
def test_signed_or_sealed_history_is_refused_before_write(case, kind):
    c = case
    data = copy.deepcopy(c["data"])
    if kind == "node":
        data["nodes"][0]["sigPubkey"] = "a" * 64
    elif kind == "ref":
        data["refs"]["retained-v1"] = {"mac": data["nodes"][0]["mac"], "sig": "b" * 128}
    elif kind == "audit":
        audit.append(
            str(c["root"]),
            "custodian",
            "tag",
            c["intent"]["ref"],
            "a" * 64,
            None,
            seq=4,
            sig="b" * 128,
            sig_pubkey="a" * 64,
        )
    elif kind == "required":
        data["manifest"]["requireSignatures"] = True
    elif kind == "seal":
        data["manifest"]["sealPubkey"] = "a" * 64
    elif kind == "baseline":
        data["manifest"]["auditBaseline"] = {}
    elif kind == "historical-seal":
        data["manifest"]["seals"] = [{"npub": "sample"}]
    _write(c, data)
    before = _snapshot(c)
    with pytest.raises(ValueError):
        _review(c)
    with pytest.raises(ValueError):
        _apply(c)
    assert _snapshot(c) == before


@pytest.mark.parametrize("kind", ["header", "node", "ref", "boolean-node"])
def test_unknown_crypto_suite_is_refused(case, kind):
    c = case
    data = copy.deepcopy(c["data"])
    if kind == "header":
        data["manifest"]["cryptoVersion"] = 2
    elif kind in {"node", "boolean-node"}:
        data["nodes"][0]["cryptoVersion"] = True if kind == "boolean-node" else 2
    else:
        data["refs"]["retained-v1"] = {
            "mac": data["nodes"][0]["mac"],
            "cryptoVersion": 2,
        }
    _write(c, data)
    before = _snapshot(c)
    with pytest.raises(ValueError):
        _review(c)
    with pytest.raises(ValueError):
        _apply(c)
    assert _snapshot(c) == before


@pytest.mark.parametrize(
    "change",
    ["metadata", "owners", "history", "category", "policy", "permission", "namespace"],
)
def test_stale_document_or_policy_is_refused_without_data_writes(case, change):
    c = case
    data = copy.deepcopy(c["data"])
    if change == "metadata":
        data["nodes"][2]["meta"]["title"] = "Unrelated update invalidates the plan"
    elif change == "owners":
        for n in data["nodes"][:2]:
            n["owners"] = ["project-human"]
    elif change == "history":
        data["nodes"][0]["locations"][0]["path"] = "different.txt"
    elif change == "category":
        data["nodes"][0]["category"] = "category-4-sample"
    elif change == "namespace":
        data["manifest"]["namespace"] = "different"
    elif change == "policy":
        c["org"]["policies"]["security_categories"]["category-2"]["label"] = (
            "Updated policy"
        )
        c["policy"].write_text(yaml.safe_dump(c["org"]), encoding="utf-8")
    else:
        c["org"]["roles"][0]["access_level"] = "old"
        c["policy"].write_text(yaml.safe_dump(c["org"]), encoding="utf-8")
    _write(c, data)
    before = _snapshot(c)
    with pytest.raises(ValueError):
        _apply(c)
    assert _snapshot(c) == before


@pytest.mark.parametrize("actor", ["unknown", "project-human", "organization-reader"])
def test_unauthorized_actor_cannot_plan_or_apply(case, actor):
    before = _snapshot(case)
    with pytest.raises(ValueError):
        local.review(str(case["root"]), str(case["policy"]), actor, **case["intent"])
    with pytest.raises(ValueError):
        _apply(case, actor=actor)
    assert _snapshot(case) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("next_seq", True),
        ("audit_count", False),
        ("next_seq", -1),
        ("schema", "unknown"),
        ("mode", "signed"),
        ("unexpected", 1),
    ],
)
def test_malformed_plan_is_refused(case, field, value):
    plan = dict(case["plan"], **{field: value})
    before = _snapshot(case)
    with pytest.raises(ValueError):
        _apply(case, plan=plan)
    assert _snapshot(case) == before


@posix
def test_interrupted_commit_resumes_without_duplicate_receipt(case, monkeypatch):
    c = case
    save = manifest.save
    monkeypatch.setattr(
        manifest,
        "save",
        lambda *_: (_ for _ in ()).throw(OSError("injected write failure")),
    )
    with pytest.raises(OSError):
        _apply(c)
    pending = (c["root"] / "audit.log").read_bytes()
    assert len(pending.splitlines()) == 4
    assert manifest.load(str(c["path"])) == c["data"]
    monkeypatch.setattr(manifest, "save", save)
    assert _apply(c)["resumed"] is True
    assert (c["root"] / "audit.log").read_bytes() == pending
    assert _apply(c)["unchanged"] is True


@posix
def test_committed_write_with_late_error_is_an_unchanged_retry(case, monkeypatch):
    save = manifest.save

    def late_error(*args):
        save(*args)
        raise OSError("injected late error")

    monkeypatch.setattr(manifest, "save", late_error)
    with pytest.raises(OSError):
        _apply(case)
    before = _snapshot(case)
    monkeypatch.setattr(manifest, "save", save)
    assert _apply(case)["unchanged"] is True
    assert _snapshot(case) == before


@pytest.mark.parametrize("tail", [b'{"incomplete":', b"\n", b"not JSON\n"])
def test_unknown_or_torn_audit_is_preserved(case, tail):
    with (case["root"] / "audit.log").open("ab") as stream:
        stream.write(tail)
    before = _snapshot(case)
    with pytest.raises(ValueError):
        _apply(case)
    assert _snapshot(case) == before


@pytest.mark.parametrize(
    "change",
    [
        "policy",
        "manifest",
        "receipt-mode",
        "receipt-plan",
        "receipt-uid",
        "unknown-tail",
    ],
)
def test_pending_receipt_or_changed_source_requires_review(case, change):
    c = case
    details = {
        "schema": "phantomdocs.local-classification-receipt/v1",
        "mode": local.MODE,
        "plan": copy.deepcopy(c["plan"]),
        "operator_uid": None,
    }
    if change == "receipt-mode":
        details["mode"] = "other-mode"
    elif change == "receipt-plan":
        details["plan"]["reason"] = "Different request"
    elif change == "receipt-uid":
        details["operator_uid"] = True
    audit.append(
        str(c["root"]),
        "custodian",
        local.ACTION,
        c["intent"]["ref"],
        c["intent"]["expected_mac"],
        None,
        seq=4,
        details=details,
    )
    if change == "policy":
        c["org"]["policies"]["security_categories"]["category-2"]["label"] = (
            "Changed policy"
        )
        c["policy"].write_text(yaml.safe_dump(c["org"]), encoding="utf-8")
    elif change == "manifest":
        data = copy.deepcopy(c["data"])
        data["nodes"][2]["meta"]["title"] = "Changed metadata"
        _write(c, data)
    elif change == "unknown-tail":
        audit.append(
            str(c["root"]),
            "custodian",
            "unknown",
            c["intent"]["ref"],
            "a" * 64,
            None,
            seq=5,
        )
    before = _snapshot(c)
    with pytest.raises(ValueError):
        _apply(c)
    assert _snapshot(c) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("auditSeq", None),
        ("auditSeq", True),
        ("auditSeq", 0),
        ("auditHead", "0" * 64),
        ("headSeq", 1),
    ],
)
def test_missing_or_inconsistent_checkpoint_is_refused(case, field, value):
    data = copy.deepcopy(case["data"])
    data["manifest"][field] = value
    _write(case, data)
    before = _snapshot(case)
    with pytest.raises(ValueError):
        _review(case)
    assert _snapshot(case) == before


def test_json_plan_rejects_duplicate_fields_and_oversize(case):
    path = case["root"] / "review.json"
    path.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        local.read_plan(str(path))
    path.write_text(" " * 65537, encoding="utf-8")
    with pytest.raises(ValueError, match="64 KiB"):
        local.read_plan(str(path))


def test_cli_plan_and_explicit_operator_acknowledgment(case):
    c = case
    i = c["intent"]
    before = _snapshot(c)
    result = _invoke(
        c,
        "classification-local-plan",
        i["ref"],
        "--expected-mac",
        i["expected_mac"],
        "--expected-category",
        i["expected_category"],
        "--category",
        i["target_category"],
        "--reason",
        i["reason"],
    )
    assert result.exit_code == 0, result.output
    plan = json.loads(result.output)
    assert plan == c["plan"]
    path = c["root"] / "review.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    refused = _invoke(c, "classification-local-apply", "--review", str(path))
    assert refused.exit_code != 0 and "--trusted-local" in refused.output
    assert _snapshot(c) == before


@posix
def test_cli_apply_uses_native_local_transaction(case):
    path = case["root"] / "review.json"
    path.write_text(json.dumps(case["plan"]), encoding="utf-8")
    result = _invoke(
        case, "classification-local-apply", "--review", str(path), "--trusted-local"
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["versions_reclassified"] == 2
