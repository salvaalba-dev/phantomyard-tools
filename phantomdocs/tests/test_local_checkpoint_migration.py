"""One-time unsigned migration preserves legacy bytes without accessing keys."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest
import test_audit_baseline as baseline_cases
import yaml
from click.testing import CliRunner

from phantomdocs import audit, cli, documents, manifest

posix = baseline_cases.posix


@pytest.fixture
def legacy(tmp_path):
    return baseline_cases.legacy.__wrapped__(tmp_path)


@pytest.fixture
def migration():
    path = Path(__file__).resolve().parents[1] / "contrib" / "legacy_checkpoint.py"
    spec = importlib.util.spec_from_file_location("local_checkpoint_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _apply(migration, case, **kwargs):
    args = {
        "root": str(case["root"]),
        "org_path": str(case["policy"]),
        "actor": "custodian",
        "plan": case["plan"],
        "reason": "Reviewed local migration",
    }
    args.update(kwargs)
    return migration.apply(**args)


def test_plan_is_read_only_and_generic(migration, legacy):
    c = legacy
    result = migration.review(str(c["root"]), str(c["policy"]), "custodian")
    assert result == c["plan"]
    assert c["manifest"].read_bytes() == c["manifest_before"]
    assert (c["root"] / "audit.log").read_bytes() == c["audit_before"]
    assert not (c["root"] / "manifest.lock").exists()


@posix
def test_apply_preserves_every_old_byte_and_does_not_load_keys(
    migration, legacy, monkeypatch
):
    c = legacy
    monkeypatch.setenv("PHANTOMDOCS_NSEC", "must-not-be-read")
    monkeypatch.setattr(documents, "_signing_key", lambda *_: pytest.fail("key access"))
    monkeypatch.setattr(audit, "truncate", lambda *_: pytest.fail("truncation"))
    result = _apply(migration, c)
    assert result == {
        "unchanged": False,
        "resumed": False,
        "signed": False,
        "preserved_entries": 3,
        "seq": 1,
    }
    raw = (c["root"] / "audit.log").read_bytes()
    assert raw.startswith(c["audit_before"]) and len(raw.splitlines()) == 4
    row = json.loads(raw.splitlines()[-1])
    assert row["action"] == "migrate-legacy-checkpoint"
    assert row["details"]["mode"] == "unsigned-local-admin"
    assert "sig" not in row and "sigPubkey" not in row
    data = manifest.load(str(c["manifest"]))
    assert "auditBaseline" not in data["manifest"]
    assert data["manifest"]["auditSeq"] == 4
    assert data["manifest"]["auditHead"] == audit.head(str(c["root"]))[1]
    for field in ("nodes", "refs", "currentVersions"):
        assert data[field] == c["data"][field]
    assert c["blob"].read_bytes() == b"Fictional legacy document"
    verified = CliRunner().invoke(
        cli.main, ["verify", "--root", str(c["root"]), "--org-yaml", str(c["policy"])]
    )
    assert verified.exit_code == 0, verified.output
    before = raw, c["manifest"].read_bytes()
    assert _apply(migration, c)["unchanged"] is True
    assert before == (
        (c["root"] / "audit.log").read_bytes(),
        c["manifest"].read_bytes(),
    )


@pytest.mark.parametrize(
    "kind", ["node", "audit", "profile", "seal-history", "signed-baseline"]
)
def test_signed_or_sealed_stores_are_never_downgraded(migration, legacy, kind):
    c = legacy
    data = copy.deepcopy(c["data"])
    if kind == "node":
        data["nodes"][0]["sig"] = "a" * 128
    elif kind == "audit":
        audit.append(
            str(c["root"]),
            "custodian",
            "add",
            "urn:sample-org:doc:item",
            "a" * 64,
            None,
            sig="a" * 128,
        )
    elif kind == "profile":
        data["manifest"]["requireSignatures"] = True
    elif kind == "seal-history":
        data["manifest"]["seals"] = [
            {
                "cs": 1,
                "npub": "npub1example",
                "ts": "2026-01-01T00:00:00Z",
                "sig": "a" * 128,
            }
        ]
    else:
        data["manifest"]["auditBaseline"] = {}
    c["manifest"].write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError):
        migration.review(str(c["root"]), str(c["policy"]), "custodian")


@posix
@pytest.mark.parametrize("change", ["policy", "authority", "manifest", "plan", "actor"])
def test_apply_rechecks_authority_and_snapshot(migration, legacy, change):
    c = legacy
    kwargs = {}
    if change in ("policy", "authority"):
        org = copy.deepcopy(c["org"])
        if change == "policy":
            org["organization"]["name"] = "Changed policy snapshot"
        else:
            org["actors"][0]["role"] = "worker"
        c["policy"].write_text(yaml.safe_dump(org))
    elif change == "manifest":
        data = copy.deepcopy(c["data"])
        data["nodes"][0]["meta"]["review"] = "changed"
        c["manifest"].write_text(yaml.safe_dump(data))
    elif change == "plan":
        plan = copy.deepcopy(c["plan"])
        plan["audit_digest"] = "b" * 64
        kwargs["plan"] = plan
    else:
        kwargs["actor"] = "worker"
    before = c["manifest"].read_bytes(), (c["root"] / "audit.log").read_bytes()
    with pytest.raises(ValueError):
        _apply(migration, c, **kwargs)
    assert before == (
        c["manifest"].read_bytes(),
        (c["root"] / "audit.log").read_bytes(),
    )


@posix
def test_pending_retry_finishes_once_without_truncating(migration, legacy, monkeypatch):
    c = legacy
    save = manifest.save
    monkeypatch.setattr(
        manifest, "save", lambda *_: (_ for _ in ()).throw(OSError("interrupted"))
    )
    with pytest.raises(OSError):
        _apply(migration, c)
    assert c["manifest"].read_bytes() == c["manifest_before"]
    pending = (c["root"] / "audit.log").read_bytes()
    assert pending.startswith(c["audit_before"])
    service = documents.DocumentService(
        str(c["root"]),
        str(c["policy"]),
        "custodian",
        signing_key_from_environment=False,
    )
    with pytest.raises(documents.DocumentError, match="legacy audit log"):
        service._reconcile_audit(
            manifest.ManifestRepository(manifest.load(str(c["manifest"])))
        )
    assert (c["root"] / "audit.log").read_bytes() == pending
    monkeypatch.setattr(manifest, "save", save)
    assert _apply(migration, c)["resumed"] is True
    assert (c["root"] / "audit.log").read_bytes() == pending


@posix
def test_torn_append_is_preserved_for_review(migration, legacy, monkeypatch):
    c = legacy

    def broken(*_args, **_kwargs):
        with (c["root"] / "audit.log").open("ab") as stream:
            stream.write(b'{"torn":')
        raise OSError("interrupted")

    monkeypatch.setattr(audit, "append", broken)
    with pytest.raises(OSError):
        _apply(migration, c)
    torn = (c["root"] / "audit.log").read_bytes()
    with pytest.raises(ValueError):
        _apply(migration, c)
    assert (c["root"] / "audit.log").read_bytes() == torn
    assert torn.startswith(c["audit_before"])
    assert c["manifest"].read_bytes() == c["manifest_before"]


@posix
def test_post_commit_failure_is_idempotent(migration, legacy, monkeypatch):
    c = legacy
    save = manifest.save

    def committed(*args):
        save(*args)
        raise OSError("client interrupted after commit")

    monkeypatch.setattr(manifest, "save", committed)
    with pytest.raises(OSError):
        _apply(migration, c)
    raw = (c["root"] / "audit.log").read_bytes()
    monkeypatch.setattr(manifest, "save", save)
    assert _apply(migration, c)["unchanged"] is True
    assert (c["root"] / "audit.log").read_bytes() == raw


@posix
def test_existing_unsigned_service_can_continue_after_migration(migration, legacy):
    c = legacy
    _apply(migration, c)
    service = documents.DocumentService(
        str(c["root"]),
        str(c["policy"]),
        "custodian",
        signing_key_from_environment=False,
    )
    service.create_folder(
        name="next-folder", parent=None, category="category-2", owners=["administrator"]
    )
    data = manifest.load(str(c["manifest"]))
    assert data["manifest"]["headSeq"] == 2
    assert data["manifest"]["auditSeq"] == 5
    assert not audit.verify_chain(str(c["root"]))
    assert not audit.sequence_issues(str(c["root"]))
    assert _apply(migration, c)["unchanged"] is True


@posix
@pytest.mark.parametrize("change", ["reason", "policy", "extra-tail", "receipt"])
def test_pending_conflicts_are_preserved(migration, legacy, monkeypatch, change):
    c = legacy
    save = manifest.save
    monkeypatch.setattr(
        manifest, "save", lambda *_: (_ for _ in ()).throw(OSError("interrupted"))
    )
    with pytest.raises(OSError):
        _apply(migration, c)
    monkeypatch.setattr(manifest, "save", save)
    kwargs = {}
    if change == "reason":
        kwargs["reason"] = "Different reason"
    elif change == "policy":
        org = copy.deepcopy(c["org"])
        org["organization"]["name"] = "New policy snapshot"
        c["policy"].write_text(yaml.safe_dump(org))
    elif change == "extra-tail":
        audit.append(
            str(c["root"]),
            "custodian",
            "other",
            "urn:sample-org:doc:item",
            "a" * 64,
            None,
            seq=2,
        )
    else:
        raw = (c["root"] / "audit.log").read_bytes()
        lines = raw.splitlines(keepends=True)
        row = json.loads(lines[-1])
        row["details"]["mode"] = "signed"
        lines[-1] = (json.dumps(row, sort_keys=True) + "\n").encode()
        (c["root"] / "audit.log").write_bytes(b"".join(lines))
    before = c["manifest"].read_bytes(), (c["root"] / "audit.log").read_bytes()
    with pytest.raises(ValueError):
        _apply(migration, c, **kwargs)
    assert before == (
        c["manifest"].read_bytes(),
        (c["root"] / "audit.log").read_bytes(),
    )


@pytest.mark.parametrize("value", [True, False, -1, 1.0, "1"])
def test_coercible_review_counts_are_refused(migration, legacy, value):
    plan = copy.deepcopy(legacy["plan"])
    plan["audit_count"] = value
    with pytest.raises(ValueError):
        _apply(migration, legacy, plan=plan)
    assert legacy["manifest"].read_bytes() == legacy["manifest_before"]


def test_cli_planning_does_not_sign_or_write(migration, legacy, capsys, monkeypatch):
    c = legacy
    monkeypatch.setattr(documents, "_signing_key", lambda *_: pytest.fail("key access"))
    migration.main(
        [
            "plan",
            "--root",
            str(c["root"]),
            "--org-yaml",
            str(c["policy"]),
            "--actor",
            "custodian",
        ]
    )
    assert json.loads(capsys.readouterr().out) == c["plan"]
    assert c["manifest"].read_bytes() == c["manifest_before"]
    assert (c["root"] / "audit.log").read_bytes() == c["audit_before"]
