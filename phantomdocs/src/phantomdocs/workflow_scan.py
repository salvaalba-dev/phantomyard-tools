"""Bounded metadata-only inbox planning through the existing workflow policy.

Inventory fields are observations supplied by an adapter, never authority to
execute, overwrite, publish, or clean up a document.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path

import click

from .access import can_read, normalize_category
from .manifest import node_by_path, node_by_slug, validate
from .storage import location_uri
from .workflows import WorkflowError, digest, plan, reference_is_safe

MAX_ITEMS = 1000
MAX_INVENTORY_BYTES = 4 * 1024 * 1024
_ITEM_FIELDS = {
    "id",
    "name",
    "mimeType",
    "parents",
    "size",
    "version",
    "md5Checksum",
    "trashed",
}


def read_inventory(path):
    """Read one bounded UTF-8 inventory; duplicate keys are refused."""

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise WorkflowError("duplicate inventory key")
            result[key] = value
        return result

    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INVENTORY_BYTES + 1)
    if len(raw) > MAX_INVENTORY_BYTES:
        raise WorkflowError("inventory exceeds 4 MiB")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except RecursionError as error:
        raise WorkflowError("inventory JSON nesting is excessive") from error
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, (dict, list)):
            if depth > 64:
                raise WorkflowError("inventory JSON nesting exceeds 64 levels")
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth + 1) for child in children)
    return document


def _inventory(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "complete", "items"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["complete"] is not True
        or not isinstance(value["items"], list)
        or len(value["items"]) > MAX_ITEMS
    ):
        raise WorkflowError(
            "a complete version-1 inventory of at most 1000 items is required"
        )
    seen = set()
    for item in value["items"]:
        required = {"id", "name", "mimeType", "parents"}
        if (
            not isinstance(item, dict)
            or not required <= set(item)
            or set(item) - _ITEM_FIELDS
        ):
            raise WorkflowError("invalid inventory item fields")
        if (
            not isinstance(item["id"], str)
            or len(item["id"]) > 200
            or not reference_is_safe("gdrive://" + item["id"])
            or item["id"] in seen
        ):
            raise WorkflowError("invalid or duplicate inventory identity")
        seen.add(item["id"])
        if (
            not isinstance(item["name"], str)
            or not 0 < len(item["name"]) <= 512
            or any(ord(c) < 32 or ord(c) == 127 for c in item["name"])
            or not isinstance(item["mimeType"], str)
            or not re.fullmatch(r"[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+", item["mimeType"])
            or not isinstance(item["parents"], list)
            or not item["parents"]
            or len(item["parents"]) > 10
            or any(
                not isinstance(p, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", p)
                for p in item["parents"]
            )
            or len(set(item["parents"])) != len(item["parents"])
            or "trashed" in item
            and type(item["trashed"]) is not bool
        ):
            raise WorkflowError("invalid inventory metadata")
        for field, pattern in (
            ("size", r"[0-9]{1,20}"),
            ("version", r"[0-9]{1,40}"),
            ("md5Checksum", r"[0-9a-f]{32}"),
        ):
            if field in item and (
                not isinstance(item[field], str)
                or not re.fullmatch(pattern, item[field])
            ):
                raise WorkflowError("invalid inventory fingerprint")


def scan(inventory, installation, org, registry, processor, caller, manifest, context):
    """Propose reference-document jobs without admission, byte reads or writes."""
    _inventory(inventory)
    if validate(manifest):
        raise WorkflowError("invalid native manifest structure")
    if manifest["manifest"]["org"] != org.get("organization", {}).get("id"):
        raise WorkflowError("manifest and organization differ")
    base = {
        "version": 1,
        "organization": manifest["manifest"]["org"],
        "request_id": "inbox-policy-check",
        "requester": caller,
        "context": deepcopy(context),
        "artifacts": [
            {
                "id": "original",
                "role": "original",
                "ref": "gdrive://policy-check",
                "media_type": "application/octet-stream",
            }
        ],
    }
    policy = plan(base, installation, org, registry, processor, caller)
    if policy["protocol"]["id"] != "reference-document":
        raise WorkflowError(
            "general inbox scans require the reference-document protocol"
        )
    folder = policy["destinations"]["logical_folder"]
    parent = node_by_path(manifest, folder) or node_by_slug(manifest, folder)
    if parent is None or parent.get("kind") != "folder":
        raise WorkflowError("the declared native destination folder must already exist")
    references = {}
    for node in manifest["nodes"]:
        if node["kind"] == "doc":
            if node.get("owners") is not None and any(
                not isinstance(owner, str) for owner in node["owners"]
            ):
                raise WorkflowError("invalid native reference ownership")
            for location in node.get("locations") or []:
                try:
                    uri = location_uri(location)
                except (TypeError, AttributeError, ValueError) as error:
                    raise WorkflowError("invalid native reference location") from error
                references.setdefault(uri, []).append(node)
    rows = []
    for item in inventory["items"]:
        ref = "gdrive://" + item["id"]
        row = {"ref": ref, "name": item["name"], "state": "held"}
        if policy["intake_ref"].split("://", 1)[1] not in item["parents"]:
            row["reason"] = "outside-declared-inbox"
        elif item.get("trashed", False):
            row["reason"] = "trashed-source"
        elif item["mimeType"].lower().startswith("application/vnd.google-apps."):
            row["reason"] = "native-cloud-object-needs-separate-export-review"
        elif item["name"].casefold().endswith(".intake-request.json"):
            # A control-file naming convention is only a reason to hold, not
            # evidence of authorization or of the file's contents.
            row["reason"] = "possible-intake-control-file-needs-review"
        elif (
            not all(k in item for k in ("size", "version", "md5Checksum"))
            or int(item["size"]) == 0
        ):
            row["reason"] = "incomplete-binary-fingerprint"
        elif ref in references:
            matches = references[ref]
            category, owners = (
                policy["classification"]["category"],
                policy["classification"]["owners"],
            )
            if len({n["urn"] for n in matches}) != 1 or any(
                normalize_category(n["category"]) != category
                or set(n.get("owners") or []) != set(owners)
                or n["parentMac"] != parent["mac"]
                or not can_read(org, caller, n["category"])
                for n in matches
            ):
                row["reason"] = "existing-reference-policy-or-identity-conflict"
            else:
                row.update(
                    state="indexed-reference",
                    urn=matches[0]["urn"],
                    content_reverified=False,
                    requires_current_content_check=True,
                )
        else:
            job = deepcopy(base)
            job["request_id"] = "reference-" + digest(
                {
                    "organization": base["organization"],
                    "ref": ref,
                    "fingerprint": {
                        k: item[k]
                        for k in ("size", "version", "md5Checksum", "mimeType")
                    },
                }
            )
            job["artifacts"][0].update(ref=ref, media_type=item["mimeType"])
            proposed = plan(job, installation, org, registry, processor, caller)
            row.update(
                state=proposed["status"],
                job=job,
                plan=proposed,
                metadata={
                    k: item[k] for k in ("size", "version", "md5Checksum", "mimeType")
                },
                document_version=None,
                requires_semantic_identity_check=True,
            )
        rows.append(row)
    result = {
        "version": 1,
        "kind": "document-inbox-scan",
        "organization": base["organization"],
        "status": "review-required"
        if policy["status"] == "blocked"
        or any(r["state"] in {"held", "blocked"} for r in rows)
        else "planned",
        "execution_ready": False,
        "admission": "not-performed",
        "publication": "not-performed",
        "cleanup": "not-performed",
        "identity_context": "local-planner-not-remote-sender",
        "inventory_digest": digest(inventory),
        "manifest_digest": digest(manifest),
        "policy_plan_hash": policy["plan_hash"],
        "items": rows,
    }
    result["scan_hash"] = digest(result)
    return result


@click.command("scan")
@click.option(
    "--inventory", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option(
    "--installation", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option("--registry", default=None, type=click.Path(exists=True, dir_okay=False))
@click.option("--org-yaml", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--root", required=True, type=click.Path(exists=True, file_okay=False))
@click.option(
    "--actor", default=None, help="Authenticated local planner; not a remote sender."
)
@click.option(
    "--phantombot-config", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option(
    "--phantombot-state", default=None, type=click.Path(exists=True, dir_okay=False)
)
@click.option("--domain", required=True)
@click.option("--document-type", required=True)
@click.option("--requesting-domain", required=True)
def scan_command(
    inventory,
    installation,
    registry,
    org_yaml,
    root,
    actor,
    phantombot_config,
    phantombot_state,
    domain,
    document_type,
    requesting_domain,
):
    """Plan general inbox references from a complete metadata inventory; never execute."""
    from .cli import _load_or_die, _require_acl
    from .workflows import load_registry, read_json, resolve_processor

    try:
        caller, org = _require_acl(org_yaml, actor)
        result = scan(
            read_inventory(inventory),
            read_json(installation),
            org,
            load_registry(registry),
            resolve_processor(phantombot_config, phantombot_state),
            caller,
            _load_or_die(root),
            {
                "domain": domain,
                "document_type": document_type,
                "requesting_domain": requesting_domain,
            },
        )
    except WorkflowError as error:
        raise click.ClickException(str(error)) from error
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise click.ClickException(
            "cannot load general document scan inputs"
        ) from error
    click.echo(json.dumps(result, indent=2, ensure_ascii=False))
    if result["status"] == "review-required":
        raise click.exceptions.Exit(2)
