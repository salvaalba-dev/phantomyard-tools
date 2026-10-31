"""Experimental local audit links; not an authentication boundary."""

import copy
import hashlib
import os
from pathlib import Path

from . import audit, manifest
from .access import can_read, load_org, policy_hash
from .audit_baseline import _audit_state, _canonical
from .identity import is_valid_hex64
from .local_classification import _header_valid, _unsigned
from .storage import location_uri
from .workflow_provenance_plan import prepare_link
from .workflow_receipt_store import read_receipt, trusted_receipt_directory
from .workflow_reconcile import metadata_unchanged, review_receipt
from .workflows import reference_is_safe

ACTION = "intake-link-local"
SCHEMA = "phantomdocs.intake-link-receipt/v1"
TRUST_MODE = "trusted-local-process"


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _details(plan, operator_uid):
    link = plan["link"]
    claims = {
        "inbox_ref": link["inbox_ref"],
        "archive_ref": link["archive_ref"],
        "sha256": link["content_sha256"],
    }
    return {
        "schema": SCHEMA,
        "inbox_ref": link["inbox_ref"],
        "archive_ref": link["archive_ref"],
        "inbox_name": plan["inbox_name"],
        "policy_hash": link["policy_hash"],
        "trust_mode": TRUST_MODE,
        "receipt_claims_digest": _hash(_canonical(claims)),
        "operator_uid": operator_uid,
    }


def _proposal(data, org, actor, lines, rows, intent, inbox_name):
    issues = manifest.validate(data) or manifest.structural_issues(data)
    issues = issues or manifest.mutation_sequence_issues(data)
    if issues:
        raise ValueError("invalid manifest")
    _unsigned(data, rows)
    _header_valid(data["manifest"], lines, rows)
    if not isinstance(inbox_name, str) or inbox_name not in org.get(
        "documents", {}
    ).get("inboxes", {}):
        raise ValueError("inbox is not declared in PhantomOrg")
    link = prepare_link(org=org, manifest=data, actor=actor, **intent)
    for row in rows:
        details = row.get("details") or {}
        if (
            row.get("action") == ACTION
            and details.get("inbox_ref") == link["inbox_ref"]
        ):
            raise ValueError("intake reference already has an audit link")
    return {
        "link": link,
        "inbox_name": inbox_name,
        "header": copy.deepcopy(data["manifest"]),
        "audit_count": len(lines),
        "audit_digest": _hash(b"".join(lines)),
        "audit_head": _hash(lines[-1]) if lines else None,
        "next_seq": data["manifest"]["headSeq"] + 1,
    }


def review(root, org_path, actor, *, inbox_name, **intent):
    path = Path(root) / manifest.MANIFEST_FILENAME
    before = path.read_bytes()
    data = manifest.load(str(path))
    lines, rows = _audit_state(root)
    result = _proposal(data, load_org(org_path), actor, lines, rows, intent, inbox_name)
    if path.read_bytes() != before or _audit_state(root)[0] != lines:
        raise ValueError("store changed during review")
    return result


def links_for_scan(root, data, org, actor):
    """Read locally trusted audit links; no current source bytes are checked."""
    lines, rows = _audit_state(root)
    _unsigned(data, rows)
    _header_valid(data["manifest"], lines, rows)
    links = {}
    current_policy_hash = policy_hash(org)
    for row in rows:
        if row.get("action") != ACTION:
            continue
        details = row.get("details")
        if not isinstance(details, dict) or set(details) != {
            "schema",
            "inbox_ref",
            "archive_ref",
            "inbox_name",
            "policy_hash",
            "trust_mode",
            "receipt_claims_digest",
            "operator_uid",
        }:
            raise ValueError("invalid local intake link")
        ref, archive = details["inbox_ref"], details["archive_ref"]
        if (
            any(
                not isinstance(value, str)
                or not value.startswith("gdrive://")
                or not reference_is_safe(value)
                for value in (ref, archive)
            )
            or not isinstance(details["inbox_name"], str)
            or not details["inbox_name"]
            or not isinstance(details["policy_hash"], str)
            or not is_valid_hex64(details["policy_hash"])
            or not isinstance(row.get("hash"), str)
            or not is_valid_hex64(row["hash"])
        ):
            raise ValueError("invalid local intake link fields")
        node = manifest.node_by_mac(data, row.get("mac"))
        current = manifest.node_by_urn(data, row.get("urn"))
        claims = {"inbox_ref": ref, "archive_ref": archive, "sha256": row.get("hash")}
        uid = details["operator_uid"]
        if (
            details["schema"] != SCHEMA
            or details["trust_mode"] != TRUST_MODE
            or details["receipt_claims_digest"] != _hash(_canonical(claims))
            or not (uid is None or type(uid) is int and uid >= 0)
            or not node
            or not current
            or node.get("urn") != row.get("urn")
            or node.get("contentHash") != row.get("hash")
            or not any(
                location_uri(loc) == archive for loc in (node.get("locations") or [])
            )
        ):
            raise ValueError("inconsistent local intake link")
        if ref in links:
            raise ValueError("ambiguous local intake link")
        if (
            details["policy_hash"] == current_policy_hash
            and current.get("mac") == node.get("mac")
            and current.get("contentHash") == node.get("contentHash")
            and can_read(org, actor, node["category"])
            and can_read(org, actor, current["category"])
        ):
            links[ref] = {"node": current, "inbox_name": details["inbox_name"]}
        else:
            # Retain the key to prevent a hidden link becoming a new proposal.
            links[ref] = None
    return links


def _matches(row, plan, actor):
    link = plan["link"]
    details = row.get("details")
    uid = details.get("operator_uid") if isinstance(details, dict) else None
    return (
        isinstance(details, dict)
        and (uid is None or type(uid) is int and uid >= 0)
        and row.get("action") == ACTION
        and row.get("actor") == actor
        and row.get("urn") == link["urn"]
        and row.get("mac") == link["document_mac"]
        and row.get("hash") == link["content_sha256"]
        and type(row.get("seq")) is int
        and row["seq"] == plan["next_seq"]
        and row.get("prev") == plan["audit_head"]
        and row.get("sig") is None
        and row.get("sigPubkey") is None
        and details == _details(plan, uid)
    )


def _checked_state(root, path, org_path, actor, plan, inbox_name):
    link = plan["link"]
    if link["actor"] != actor:
        raise ValueError("actor differs from reviewed plan")
    if plan["inbox_name"] != inbox_name:
        raise ValueError("inbox differs from reviewed plan")
    intent = {k: link[k] for k in ("urn", "inbox_ref", "archive_ref")}
    intent["sha256"] = link["content_sha256"]
    data = manifest.load(path)
    lines, rows = _audit_state(root)
    count = plan["audit_count"]
    pending = len(lines) == count + 1 and _matches(rows[-1], plan, actor)
    if len(lines) != count and not pending:
        raise ValueError("stale or unknown audit tail")
    prefix = lines[:count]
    if (
        _hash(b"".join(prefix)) != plan["audit_digest"]
        or (_hash(prefix[-1]) if prefix else None) != plan["audit_head"]
    ):
        raise ValueError("reviewed audit prefix changed")
    before = copy.deepcopy(data)
    committed = False
    if pending and data["manifest"] != plan["header"]:
        _header_valid(data["manifest"], lines, rows)
        expected = copy.deepcopy(plan["header"])
        expected.update(
            headSeq=plan["next_seq"], auditSeq=count + 1, auditHead=_hash(lines[-1])
        )
        if data["manifest"] != expected:
            raise ValueError("checkpoint changed")
        before["manifest"] = copy.deepcopy(plan["header"])
        committed = True
    org = load_org(org_path)
    fresh = _proposal(before, org, actor, prefix, rows[:count], intent, inbox_name)
    if _canonical(fresh) != _canonical(plan):
        raise ValueError("stale provenance plan")
    return data, lines, pending, committed, org


def _read_matching_receipt(directory, name, link):
    with trusted_receipt_directory(directory) as receipt_dir_fd:
        receipt = read_receipt(receipt_dir_fd, name)
    if receipt != {
        "inbox_ref": link["inbox_ref"],
        "archive_ref": link["archive_ref"],
        "sha256": link["content_sha256"],
    }:
        raise ValueError("receipt differs from reviewed link")
    return receipt


def apply(
    root, org_path, actor, plan, *, receipt_directory, receipt_name, inbox_name, reader
):
    """Verify a local claim outside the lock; revalidate before audit append.

    Local custody does not authenticate the original producer. Drive metadata
    is rechecked under the lock, but Drive itself is not locked by this process.
    """
    plan = copy.deepcopy(plan)
    link = plan["link"]
    path = str(Path(root) / manifest.MANIFEST_FILENAME)
    data, _, _, committed, org = _checked_state(
        root, path, org_path, actor, plan, inbox_name
    )
    if committed:
        with manifest.manifest_lock(path):
            _, _, _, still_committed, _ = _checked_state(
                root, path, org_path, actor, plan, inbox_name
            )
            if not still_committed:
                raise ValueError("committed link changed")
            return {"unchanged": True, "seq": plan["next_seq"]}
    receipt = _read_matching_receipt(receipt_directory, receipt_name, link)
    observed = review_receipt(
        receipt=receipt,
        inbox_ref=link["inbox_ref"],
        inbox_name=inbox_name,
        org=org,
        caller=actor,
        manifest=data,
        reader=reader,
    )
    if (
        observed.get("reason") != "matching-evidence"
        or observed.get("urn") != link["urn"]
    ):
        raise ValueError("current intake content not verified")
    with manifest.manifest_lock(path):
        data, lines, pending, committed, org = _checked_state(
            root, path, org_path, actor, plan, inbox_name
        )
        if committed:
            return {"unchanged": True, "seq": plan["next_seq"]}
        if _read_matching_receipt(receipt_directory, receipt_name, link) != receipt:
            raise ValueError("receipt changed during verification")
        if not metadata_unchanged(
            reader, link["inbox_ref"], observed["observed_metadata"]
        ):
            raise ValueError("intake metadata changed during verification")
        if policy_hash(load_org(org_path)) != link["policy_hash"]:
            raise ValueError("organization policy changed during verification")
        head = (
            _hash(lines[-1])
            if pending
            else audit.append(
                root,
                actor,
                ACTION,
                link["urn"],
                link["document_mac"],
                link["content_sha256"],
                seq=plan["next_seq"],
                details=_details(
                    plan, os.geteuid() if hasattr(os, "geteuid") else None
                ),
            )
        )
        data["manifest"].update(
            headSeq=plan["next_seq"], auditSeq=plan["audit_count"] + 1, auditHead=head
        )
        manifest.save(path, data)
        return {"unchanged": False, "resumed": pending, "seq": plan["next_seq"]}
