"""A general inbox scan proposes jobs but never authenticates or executes them."""

import json
from copy import deepcopy

import pytest
import test_workflows as fixtures
import yaml
from click.testing import CliRunner

from phantomdocs.cli import main
from phantomdocs.manifest import empty_manifest, validate
from phantomdocs.workflow_scan import MAX_INVENTORY_BYTES, read_inventory, scan
from phantomdocs.workflows import WorkflowError, load_registry


@pytest.fixture
def system():
    org = fixtures.model.__wrapped__()
    installation = fixtures.installation.__wrapped__()
    manifest = empty_manifest("example-org", "docs", "0" * 64)
    manifest["nodes"].append(
        {
            "kind": "folder",
            "urn": "urn:example-org:folder:project-reports",
            "mac": "1" * 64,
            "parentMac": "0" * 64,
            "slug": "project-reports",
            "category": "category-2",
            "owners": ["custodian", "project-lead"],
        }
    )
    assert not validate(manifest)
    inventory = {
        "version": 1,
        "complete": True,
        "items": [
            {
                "id": "example-file",
                "name": "Application.xlsx",
                "parents": ["shared-intake"],
                "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "size": "773",
                "version": "29",
                "md5Checksum": "a" * 32,
            }
        ],
    }
    context = {
        "domain": "projects",
        "document_type": "report",
        "requesting_domain": "projects",
    }
    return (
        inventory,
        installation,
        org,
        load_registry(),
        ("coordinator", "phantombot-config"),
        "coordinator",
        manifest,
        context,
    )


def index(system, *, category="category-2", owners=None, urn=None):
    manifest = system[6]
    node = {
        "kind": "doc",
        "urn": urn or "urn:example-org:doc:project-reports/source",
        "mac": "2" * 64,
        "parentMac": "1" * 64,
        "slug": "source",
        "category": category,
        "owners": owners if owners is not None else ["custodian", "project-lead"],
        "contentHash": "3" * 64,
        "locations": [{"backend": "gdrive", "ref": "example-file"}],
    }
    manifest["nodes"].append(node)
    assert not validate(manifest)
    return node


def test_uses_existing_policy_and_does_not_infer_document_version(system):
    original = deepcopy(system[:3] + system[6:])
    result = scan(*system)
    row = result["items"][0]
    assert row["state"] == "planned"
    assert row["plan"]["classification"] == {
        "category": "category-2",
        "owners": ["custodian", "project-lead"],
    }
    assert row["job"]["requester"] == "coordinator"
    assert row["job"]["artifacts"][0]["role"] == "original"
    assert row["document_version"] is None and row["metadata"]["version"] == "29"
    assert row["requires_semantic_identity_check"] is True
    assert not result["execution_ready"] and not row["plan"]["execution_ready"]
    assert (
        result["admission"]
        == result["publication"]
        == result["cleanup"]
        == "not-performed"
    )
    assert original == system[:3] + system[6:]


def test_repeated_scan_has_stable_jobs_and_pins(system):
    assert scan(*system) == scan(*system)


def test_metadata_order_does_not_create_another_request(system):
    before = scan(*system)["items"][0]["job"]["request_id"]
    system[0]["items"][0]["parents"].append("another-parent")
    system[0]["items"][0]["parents"].reverse()
    assert scan(*system)["items"][0]["job"]["request_id"] == before


def test_changed_drive_revision_changes_request_not_semantic_version(system):
    before = scan(*system)["items"][0]
    system[0]["items"][0]["version"] = "30"
    after = scan(*system)["items"][0]
    assert before["job"]["request_id"] != after["job"]["request_id"]
    assert after["document_version"] is None


def test_empty_scan_still_validates_the_declared_policy(system):
    system[0]["items"] = []
    assert scan(*system)["items"] == []
    system[7]["document_type"] = "unknown"
    with pytest.raises(WorkflowError):
        scan(*system)


def test_second_organization_needs_no_code_changes(system):
    system[1]["organization"] = "second-example"
    system[2]["organization"]["id"] = "second-example"
    system[6]["manifest"]["org"] = "second-example"
    system[6]["nodes"][0]["urn"] = "urn:second-example:folder:project-reports"
    assert scan(*system)["items"][0]["job"]["organization"] == "second-example"


def test_scan_never_reads_reference_bytes(system, monkeypatch):
    from phantomdocs import storage

    def forbidden(*args, **kwargs):
        pytest.fail("metadata planning must not read source bytes")

    monkeypatch.setattr(storage, "read_reference", forbidden)
    assert scan(*system)["items"][0]["state"] == "planned"


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"parents": ["other-inbox"]}, "outside-declared-inbox"),
        ({"trashed": True}, "trashed-source"),
        (
            {"mimeType": "application/vnd.google-apps.spreadsheet"},
            "native-cloud-object-needs-separate-export-review",
        ),
        (
            {"mimeType": "Application/VND.Google-Apps.Spreadsheet"},
            "native-cloud-object-needs-separate-export-review",
        ),
        ({"size": "0"}, "incomplete-binary-fingerprint"),
        (
            {"name": "application.INTAKE-REQUEST.JSON"},
            "possible-intake-control-file-needs-review",
        ),
    ],
)
def test_unresolved_sources_are_held(system, change, reason):
    system[0]["items"][0].update(change)
    result = scan(*system)
    assert result["status"] == "review-required"
    assert result["items"][0]["reason"] == reason
    assert "job" not in result["items"][0]


@pytest.mark.parametrize("field", ["size", "version", "md5Checksum"])
def test_missing_binary_fingerprint_is_held(system, field):
    del system[0]["items"][0][field]
    assert scan(*system)["items"][0]["reason"] == "incomplete-binary-fingerprint"


def test_partial_batch_preserves_independent_plans(system):
    second = deepcopy(system[0]["items"][0])
    second.update(id="other-file", parents=["other-inbox"])
    system[0]["items"].append(second)
    result = scan(*system)
    assert [row["state"] for row in result["items"]] == ["planned", "held"]


def test_existing_reference_has_no_new_job_or_content_claim(system):
    node = index(system)
    row = scan(*system)["items"][0]
    assert row["state"] == "indexed-reference" and row["urn"] == node["urn"]
    assert row["content_reverified"] is False and row["requires_current_content_check"]
    assert "job" not in row


def test_different_reference_requires_identity_review_even_if_already_indexed(system):
    node = index(system)
    node["locations"] = [{"backend": "gdrive", "ref": "archived-file"}]
    row = scan(*system)["items"][0]
    assert row["state"] == "planned"
    assert row["requires_semantic_identity_check"] is True
    assert "urn" not in row


def test_null_existing_locations_are_treated_as_no_locations(system):
    node = index(system)
    node["locations"] = None
    assert scan(*system)["items"][0]["state"] == "planned"


@pytest.mark.parametrize(
    "change",
    [{"category": "category-3"}, {"owners": ["custodian"]}, {"parentMac": "0" * 64}],
)
def test_existing_policy_conflict_does_not_reclassify_or_expose_identity(
    system, change
):
    node = index(system)
    node.update(change)
    row = scan(*system)["items"][0]
    assert row["reason"] == "existing-reference-policy-or-identity-conflict"
    assert "urn" not in row and "job" not in row


def test_reference_with_two_identities_is_held(system):
    first = index(system)
    second = deepcopy(first)
    second.update(
        mac="4" * 64, urn="urn:example-org:doc:project-reports/other", slug="other"
    )
    system[6]["nodes"].append(second)
    assert scan(*system)["items"][0]["state"] == "held"


@pytest.mark.parametrize(
    "field,value",
    [
        ("size", True),
        ("size", 773),
        ("version", False),
        ("md5Checksum", "A" * 32),
        ("trashed", 0),
        ("id", "file?token=invalid"),
        ("name", "bad\nname"),
        ("parents", ["shared-intake", "shared-intake"]),
        ("category", "category-1"),
        ("requester", "remote-lead"),
    ],
)
def test_malformed_or_authority_bearing_inventory_is_rejected(system, field, value):
    system[0]["items"][0][field] = value
    with pytest.raises(WorkflowError):
        scan(*system)


@pytest.mark.parametrize(
    "change", [{"complete": False}, {"version": True}, {"version": "1"}, {"other": 1}]
)
def test_incomplete_or_unknown_inventory_contract_is_rejected(system, change):
    system[0].update(change)
    with pytest.raises(WorkflowError):
        scan(*system)


def test_duplicate_file_ids_and_oversized_inventory_are_rejected(system):
    item = system[0]["items"][0]
    system[0]["items"].append(deepcopy(item))
    with pytest.raises(WorkflowError, match="duplicate"):
        scan(*system)
    system[0]["items"] = [dict(item, id="file-" + str(i)) for i in range(1001)]
    with pytest.raises(WorkflowError, match="1000"):
        scan(*system)


def test_bad_native_structure_is_rejected_before_reference_access(system):
    node = index(system)
    del node["category"]
    with pytest.raises(WorkflowError, match="manifest structure"):
        scan(*system)


@pytest.mark.parametrize(
    "change", [{"owners": [{}]}, {"locations": [{"backend": "gdrive", "ref": True}]}]
)
def test_malformed_native_reference_values_fail_with_workflow_error(system, change):
    index(system).update(change)
    with pytest.raises(WorkflowError):
        scan(*system)


def test_foreign_store_and_missing_folder_are_rejected(system):
    system[6]["manifest"]["org"] = "other-org"
    with pytest.raises(WorkflowError, match="differ"):
        scan(*system)
    system[6]["manifest"]["org"] = "example-org"
    system[6]["nodes"] = []
    with pytest.raises(WorkflowError, match="folder"):
        scan(*system)


def test_category_inheritance_uses_native_resolver(system):
    org = system[2]
    org["policies"]["security_categories"].update(
        {"category-4": {}, "category-4-project": {}}
    )
    org["policies"]["access_levels"]["internal"]["categories"].append(4)
    org["documents"]["naming"]["domains"][0]["types"][0]["category"] = (
        "category-4-project"
    )
    assert (
        scan(*system)["items"][0]["plan"]["classification"]["category"]
        == "category-4-project"
    )


def test_unauthorized_route_and_nonreference_protocol_are_rejected(system):
    system[2]["documents"]["naming"]["domains"][0]["types"][0]["category"] = 3
    with pytest.raises(WorkflowError):
        scan(*system)
    del system[2]["documents"]["naming"]["domains"][0]["types"][0]["category"]
    system[1]["routes"][0].update(
        protocol="meeting-publication", branding_profile="example"
    )
    with pytest.raises(WorkflowError):
        scan(*system)


def test_missing_capability_is_blocked(system):
    system[1]["tools"] = {}
    result = scan(*system)
    assert (
        result["status"] == "review-required"
        and result["items"][0]["state"] == "blocked"
    )


def test_bounded_utf8_json_and_duplicate_keys(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_bytes(b'{"version":1,"version":1}')
    with pytest.raises(WorkflowError, match="duplicate"):
        read_inventory(path)
    path.write_bytes(b" " * (MAX_INVENTORY_BYTES + 1))
    with pytest.raises(WorkflowError, match="4 MiB"):
        read_inventory(path)
    path.write_bytes(b"\xff")
    with pytest.raises(UnicodeError):
        read_inventory(path)
    path.write_bytes(b"[" * 2000 + b"0" + b"]" * 2000)
    with pytest.raises(WorkflowError, match="nesting"):
        read_inventory(path)


def test_cli_does_not_write_inventory_manifest_or_create_ledger(
    system, tmp_path, monkeypatch
):
    from phantomdocs import cli

    monkeypatch.setattr(cli, "_require_acl", lambda *_: ("coordinator", system[2]))
    paths = {
        name: tmp_path / name
        for name in [
            "inventory.json",
            "installation.json",
            "org.yaml",
            "config.toml",
            "manifest.yaml",
        ]
    }
    paths["inventory.json"].write_text(json.dumps(system[0]), encoding="utf-8")
    paths["installation.json"].write_text(json.dumps(system[1]), encoding="utf-8")
    paths["org.yaml"].write_text(yaml.safe_dump(system[2]), encoding="utf-8")
    paths["manifest.yaml"].write_text(yaml.safe_dump(system[6]), encoding="utf-8")
    paths["config.toml"].write_text(
        'default_persona = "coordinator"\n', encoding="utf-8"
    )
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    args = [
        "workflow",
        "scan",
        "--inventory",
        str(paths["inventory.json"]),
        "--installation",
        str(paths["installation.json"]),
        "--org-yaml",
        str(paths["org.yaml"]),
        "--phantombot-config",
        str(paths["config.toml"]),
        "--root",
        str(tmp_path),
        "--domain",
        "projects",
        "--document-type",
        "report",
        "--requesting-domain",
        "projects",
    ]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["execution_ready"] is False
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
    system[0]["items"][0]["parents"] = ["other-inbox"]
    paths["inventory.json"].write_text(json.dumps(system[0]), encoding="utf-8")
    result = CliRunner().invoke(main, args)
    assert (
        result.exit_code == 2
        and json.loads(result.output)["status"] == "review-required"
    )
