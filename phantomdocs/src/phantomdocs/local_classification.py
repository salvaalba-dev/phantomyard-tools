"""Explicit, audited classification changes for trusted local unsigned stores.

This is not remote actor authentication. The operator already controls the
authoritative store and selects a declared custodian with write access on both
sides. Signed or sealed history is never rewritten by this operation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from . import audit, manifest
from .access import load_org
from .audit_baseline import _audit_state, _canonical, _read_private_json
from .classification import classification_plan

SCHEMA = "phantomdocs.local-classification-plan/v1"
ACTION = "classify-local"
MODE = "unsigned-local-custodian"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unsigned(data: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    header = data["manifest"]
    if type(header.get("version")) is not int or header["version"] != 1:
        raise ValueError("local classification requires manifest version 1")
    crypto = header.get("cryptoVersion")
    # Only the reviewed v1 MAC suite keeps category outside content identity.
    # A future suite requires its own metadata-mutation review.
    if crypto is not None and (type(crypto) is not int or crypto != 1):
        raise ValueError("unsupported local classification crypto version")
    if any(
        header.get(k) is not None
        for k in (
            "auditBaseline",
            "signedRootMac",
            "sealPubkey",
            "sealIdentityNpub",
            "sealedHeadSeq",
            "profileTransition",
        )
    ) or any(
        header.get(k)
        for k in (
            "requireSignatures",
            "sealKeys",
            "seals",
            "revocations",
        )
    ):
        raise ValueError("local classification requires unsigned, unsealed history")
    records = (
        list(data["nodes"])
        + rows
        + [ref for ref in data.get("refs", {}).values() if isinstance(ref, dict)]
    )
    if any(
        r.get("cryptoVersion") is not None
        and (type(r["cryptoVersion"]) is not int or r["cryptoVersion"] != 1)
        for r in records
    ):
        raise ValueError("unsupported record crypto version for local classification")
    if any(r.get("sig") is not None or r.get("sigPubkey") is not None for r in records):
        raise ValueError("signed records require a separate classification operation")


def _header_valid(
    header: dict[str, Any], lines: list[bytes], rows: list[dict[str, Any]]
) -> None:
    count, head = len(lines), _digest(lines[-1]) if lines else None
    for field in ("headSeq", "auditSeq"):
        if type(header.get(field)) is not int or header[field] < 0:
            raise ValueError(
                "a reviewed audit checkpoint is required before classification"
            )
    seq = max((r["seq"] for r in rows if type(r.get("seq")) is int), default=0)
    if (
        header["auditSeq"] != count
        or header.get("auditHead") != head
        or header["headSeq"] != seq
    ):
        raise ValueError(
            "audit checkpoint differs from history; preserve it for review"
        )


def _plan(
    data,
    org,
    actor,
    lines,
    rows,
    *,
    ref,
    expected_mac,
    expected_category,
    target_category,
    reason,
):
    issues = manifest.validate(data) or manifest.structural_issues(data)
    issues = issues or manifest.mutation_sequence_issues(data)
    if issues:
        raise ValueError("manifest verification failed: " + "; ".join(issues))
    if org.get("organization", {}).get("id") != data["manifest"]["org"]:
        raise ValueError("organization identity does not match the namespace")
    _unsigned(data, rows)
    _header_valid(data["manifest"], lines, rows)
    result = classification_plan(
        data,
        org,
        actor,
        ref=ref,
        expected_mac=expected_mac,
        expected_category=expected_category,
        target_category=target_category,
        reason=reason,
    )
    # Classification is metadata on every retained unsigned version, not an
    # overlay. Existing readers therefore see the effective category directly.
    result.update(
        schema=SCHEMA,
        status="local-review-required",
        mode=MODE,
        execution_available=True,
        blockers=[],
        expected_header=copy.deepcopy(data["manifest"]),
        audit_count=len(lines),
        audit_digest=_digest(b"".join(lines)),
        audit_head=_digest(lines[-1]) if lines else None,
        next_seq=data["manifest"]["headSeq"] + 1,
    )
    return result


def review(root: str, org_path: str, actor: str, **intent) -> dict[str, Any]:
    """Read a consistent local plan without creating a lock or accessing originals."""
    path = Path(root) / manifest.MANIFEST_FILENAME
    before = path.read_bytes()
    data = manifest.load(str(path))
    lines, rows = _audit_state(root)
    org = load_org(org_path)
    result = _plan(data, org, actor, lines, rows, **intent)
    # A plan is not an authorization. Application reloads everything under the
    # writer lock; reject a concurrent scan rather than publishing mixed guards.
    if path.read_bytes() != before or _audit_state(root)[0] != lines:
        raise ValueError("store changed during review; prepare a new plan")
    return result


def read_plan(path: str) -> dict[str, Any]:
    """Bounded, duplicate-free JSON; application validates against current state."""
    plan = _read_private_json(path)
    _check_plan(plan)
    return plan


def _check_plan(plan):
    fields = {
        "schema",
        "status",
        "mode",
        "execution_available",
        "blockers",
        "expected_header",
        "audit_count",
        "audit_digest",
        "audit_head",
        "next_seq",
        "history_scope",
        "actor",
        "urn",
        "expected_current_mac",
        "expected_manifest_digest",
        "expected_policy_hash",
        "from_category",
        "target_category",
        "owners",
        "reason",
        "versions",
        "reader_impact",
    }
    if (
        not isinstance(plan, dict)
        or set(plan) != fields
        or plan.get("schema") != SCHEMA
        or plan.get("mode") != MODE
        or plan.get("history_scope") != "all-versions"
        or plan.get("execution_available") is not True
        or plan.get("blockers") != []
        or plan.get("status") != "local-review-required"
        or not isinstance(plan.get("expected_header"), dict)
        or not isinstance(plan.get("actor"), str)
        or not isinstance(plan.get("urn"), str)
    ):
        raise ValueError("invalid local classification plan")
    for field in ("audit_count", "next_seq"):
        if type(plan.get(field)) is not int or plan[field] < (
            1 if field == "next_seq" else 0
        ):
            raise ValueError("invalid local classification counter")
    _canonical(plan)


def _intent(plan):
    return {
        "ref": plan["urn"],
        "expected_mac": plan["expected_current_mac"],
        "expected_category": plan["from_category"],
        "target_category": plan["target_category"],
        "reason": plan["reason"],
    }


def _receipt_matches(row, plan):
    details = row.get("details")
    return (
        isinstance(details, dict)
        and set(details) == {"schema", "mode", "plan", "operator_uid"}
        and details["schema"] == "phantomdocs.local-classification-receipt/v1"
        and details["mode"] == MODE
        and _canonical(details["plan"]) == _canonical(plan)
        and (
            details["operator_uid"] is None
            or type(details["operator_uid"]) is int
            and details["operator_uid"] >= 0
        )
        and row.get("action") == ACTION
        and row.get("actor") == plan["actor"]
        and row.get("urn") == plan["urn"]
        and row.get("mac") == plan["expected_current_mac"]
        and row.get("hash") is None
        and type(row.get("seq")) is int
        and row["seq"] == plan["next_seq"]
        and row.get("prev") == plan["audit_head"]
        and row.get("sig") is None
        and row.get("sigPubkey") is None
    )


def apply(root: str, org_path: str, actor: str, plan: dict[str, Any]) -> dict[str, Any]:
    """Atomically reclassify all unsigned versions; append exactly one receipt.

    Retry the same plan after an audit-first interrupted commit. Never truncate
    unknown or partial tails. Immediate committed retries are no-ops; later
    unrelated mutations make an old plan stale and require a new review.
    """
    plan = json.loads(_canonical(plan))
    _check_plan(plan)
    if actor != plan["actor"]:
        raise ValueError("actor differs from reviewed local classification")
    path = str(Path(root) / manifest.MANIFEST_FILENAME)
    with manifest.manifest_lock(path):
        org = load_org(org_path)
        data = manifest.load(path)
        lines, rows = _audit_state(root)
        _unsigned(data, rows)
        count = plan["audit_count"]
        pending = len(lines) == count + 1 and _receipt_matches(rows[-1], plan)
        if len(lines) != count and not pending:
            raise ValueError("stale or unknown audit tail; preserve history for review")
        prefix = lines[:count]
        if (
            _digest(b"".join(prefix)) != plan["audit_digest"]
            or (_digest(prefix[-1]) if prefix else None) != plan["audit_head"]
        ):
            raise ValueError("reviewed audit prefix changed")
        before = copy.deepcopy(data)
        committed = False
        if pending and data["manifest"] != plan["expected_header"]:
            _header_valid(data["manifest"], lines, rows)
            expected = copy.deepcopy(plan["expected_header"])
            expected.update(
                headSeq=plan["next_seq"],
                auditSeq=count + 1,
                auditHead=_digest(lines[-1]),
            )
            if data["manifest"] != expected:
                raise ValueError("checkpoint changed since the reviewed classification")
            before["manifest"] = copy.deepcopy(plan["expected_header"])
            for node in before["nodes"]:
                if node.get("urn") == plan["urn"]:
                    if node["category"] != plan["target_category"]:
                        raise ValueError(
                            "committed classification no longer matches its receipt"
                        )
                    node["category"] = plan["from_category"]
            committed = True
        fresh = _plan(before, org, actor, prefix, rows[:count], **_intent(plan))
        if _canonical(fresh) != _canonical(plan):
            raise ValueError(
                "stale classification plan; review current document and policy"
            )
        if committed:
            return {"unchanged": True, "signed": False, "seq": plan["next_seq"]}
        changed = copy.deepcopy(data)
        for node in changed["nodes"]:
            if node.get("urn") == plan["urn"]:
                node["category"] = plan["target_category"]
        if pending:
            head = _digest(lines[-1])
        else:
            details = {
                "schema": "phantomdocs.local-classification-receipt/v1",
                "mode": MODE,
                "plan": plan,
                "operator_uid": os.geteuid() if hasattr(os, "geteuid") else None,
            }
            head = audit.append(
                root,
                actor,
                ACTION,
                plan["urn"],
                plan["expected_current_mac"],
                None,
                seq=plan["next_seq"],
                details=details,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
        changed["manifest"].update(
            headSeq=plan["next_seq"], auditSeq=count + 1, auditHead=head
        )
        manifest.save(path, changed)
        return {
            "unchanged": False,
            "resumed": pending,
            "signed": False,
            "seq": plan["next_seq"],
            "versions_reclassified": len(plan["versions"]),
        }
