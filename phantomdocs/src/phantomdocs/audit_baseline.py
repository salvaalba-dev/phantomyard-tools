"""Explicit, signed adoption of legacy audit checkpoints without truncation."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from . import audit
from .access import can_administer_namespace, key_valid_at, key_valid_now, policy_hash
from .documents import DocumentError, _now_iso
from .identity import is_valid_hex64
from .manifest import (
    MANIFEST_FILENAME,
    ManifestRepository,
    load,
    manifest_lock,
    mutation_sequence_issues,
    structural_issues,
    validate,
)
from .signing import CRYPTO_VERSION, pubkey_from_nsec, sign_mutation, verify_mutation

_ACTION = "adopt-audit-checkpoint"
_DOMAIN = b"phantomdocs-audit-baseline-v1\x00"
_PLAN_FIELDS = {
    "schema",
    "actor",
    "org",
    "namespace",
    "root_mac",
    "manifest_digest",
    "policy_hash",
    "audit_count",
    "audit_head",
    "audit_digest",
    "next_seq",
    "structural_head",
    "node_count",
    "unsigned_nodes",
}


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("checkpoint state must contain canonical JSON values") from exc


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hash(value: Any) -> bool:
    return isinstance(value, str) and is_valid_hex64(value)


def _raw(root: str) -> bytes:
    path = os.path.join(root, audit.AUDIT_FILENAME)
    if not os.path.exists(path):
        return b""
    with open(path, "rb") as stream:
        return stream.read()


def _audit_state(root: str) -> tuple[list[bytes], list[dict[str, Any]]]:
    raw = _raw(root)
    lines = raw.splitlines(keepends=True)
    if any(not line.strip() or not line.endswith(b"\n") for line in lines):
        raise ValueError(
            "audit has blank or incomplete lines; separate review required"
        )
    try:
        rows = [json.loads(line) for line in lines]
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("audit contains an invalid JSON entry") from exc
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("audit entries must be mappings")
    problems = audit.verify_chain(root) + audit.sequence_issues(root)
    if problems:
        raise ValueError("audit verification failed: " + "; ".join(problems))
    if raw != _raw(root):
        raise ValueError("audit changed while preparing its checkpoint")
    return lines, rows


def _validate_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict) or set(plan) != _PLAN_FIELDS:
        raise ValueError("invalid closed audit-checkpoint plan schema")
    if plan["schema"] != "phantomdocs.audit-checkpoint-plan/v1":
        raise ValueError("unsupported audit-checkpoint plan version")
    for field in ("actor", "org", "namespace"):
        value = plan[field]
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise ValueError(f"invalid checkpoint plan {field}")
    for field in (
        "root_mac",
        "manifest_digest",
        "policy_hash",
        "audit_head",
        "audit_digest",
        "structural_head",
    ):
        if not _hash(plan[field]):
            raise ValueError(f"invalid checkpoint plan {field}")
    for field in ("audit_count", "next_seq", "node_count", "unsigned_nodes"):
        minimum = 1 if field in ("audit_count", "next_seq") else 0
        if type(plan[field]) is not int or plan[field] < minimum:
            raise ValueError(f"invalid checkpoint plan {field}")
    if plan["unsigned_nodes"] > plan["node_count"]:
        raise ValueError("invalid checkpoint plan unsigned-node count")


def _read_private_json(path: str) -> dict[str, Any]:
    """Read a bounded, unambiguous private JSON review artifact."""

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate checkpoint plan field")
            result[key] = value
        return result

    with open(path, "rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("checkpoint plan exceeds 64 KiB")
    return json.loads(raw, object_pairs_hook=unique)


def read_checkpoint_plan(path: str) -> dict[str, Any]:
    """Read a closed checkpoint plan without ambiguous duplicate fields."""
    plan = _read_private_json(path)
    _validate_plan(plan)
    return plan


def read_signed_checkpoint(path: str) -> dict[str, Any]:
    """Read a bounded externally signed record; authorization is checked on apply."""
    record = _read_private_json(path)
    if not _record_valid(record):
        raise ValueError("invalid external checkpoint signature")
    return record


def checkpoint_plan(
    root: str, data: dict[str, Any], org: dict[str, Any], actor: str
) -> dict[str, Any]:
    """Review observed legacy bytes; a plan never authorizes adoption by itself."""
    if not can_administer_namespace(org, actor):
        raise ValueError("denied: a namespace administrator must review the checkpoint")
    if (
        not isinstance(data, dict)
        or validate(data)
        or structural_issues(data)
        or mutation_sequence_issues(data)
    ):
        raise ValueError("manifest structure must pass verification before adoption")
    header = data["manifest"]
    crypto = header.get("cryptoVersion")
    if (
        type(header.get("version")) is not int
        or header["version"] != 1
        or (
            crypto is not None and (type(crypto) is not int or crypto != CRYPTO_VERSION)
        )
    ):
        raise ValueError(
            "unsupported namespace or crypto version for checkpoint adoption"
        )
    if org.get("organization", {}).get("id") != header["org"]:
        raise ValueError("organization identity does not match the namespace")
    if (
        header.get("auditSeq") is not None
        or header.get("auditHead") is not None
        or header.get("auditBaseline") is not None
    ):
        raise ValueError(
            "namespace already has a full or partial checkpoint; do not adopt it as legacy"
        )
    if header.get("signedRootMac") is not None or header.get("sealPubkey") is not None:
        raise ValueError("sealed legacy namespaces require a separate migration review")
    lines, rows = _audit_state(root)
    if not rows:
        raise ValueError("an empty audit log does not require legacy adoption")
    if any(row.get("action") == _ACTION for row in rows):
        raise ValueError(
            "an adoption attempt is pending; retry its original reviewed plan"
        )
    seqs = (
        [header.get("headSeq")]
        + [n.get("seq") for n in data["nodes"]]
        + [r.get("seq") for r in rows]
    )
    if any(type(seq) is not int or seq < 0 for seq in seqs if seq is not None):
        raise ValueError("invalid historical mutation sequence")
    plan = {
        "schema": "phantomdocs.audit-checkpoint-plan/v1",
        "actor": actor,
        "org": header["org"],
        "namespace": header["namespace"],
        "root_mac": header["rootMac"],
        "manifest_digest": _digest(_canonical(data)),
        "policy_hash": policy_hash(org),
        "audit_count": len(lines),
        "audit_head": _digest(lines[-1]),
        "audit_digest": _digest(b"".join(lines)),
        "next_seq": max([0] + [seq for seq in seqs if seq is not None]) + 1,
        "structural_head": data["nodes"][-1]["mac"]
        if data["nodes"]
        else header["rootMac"],
        "node_count": len(data["nodes"]),
        "unsigned_nodes": sum(not node.get("sig") for node in data["nodes"]),
    }
    _validate_plan(plan)
    return plan


def _envelope(payload: dict[str, Any]) -> bytes:
    if not isinstance(payload, dict) or set(payload) != {
        "version",
        "action",
        "plan",
        "reason",
        "issued_at",
        "seq",
    }:
        raise ValueError("invalid audit-baseline payload schema")
    if (
        type(payload["version"]) is not int
        or payload["version"] != 1
        or payload["action"] != _ACTION
    ):
        raise ValueError("unsupported audit-baseline payload")
    _validate_plan(payload["plan"])
    if type(payload["seq"]) is not int or payload["seq"] != payload["plan"]["next_seq"]:
        raise ValueError("audit-baseline sequence does not match the plan")
    reason, stamp = payload["reason"], payload["issued_at"]
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or reason != reason.strip()
        or len(reason) > 1024
    ):
        raise ValueError(
            "a non-empty review reason of at most 1024 characters is required"
        )
    if not isinstance(stamp, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp
    ):
        raise ValueError("audit-baseline timestamp must be UTC at second precision")
    datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S%z")
    return _DOMAIN + _canonical(payload)


def _record_valid(record: dict[str, Any]) -> bool:
    try:
        if not isinstance(record, dict) or set(record) != {
            "payload",
            "sig",
            "sigPubkey",
        }:
            return False
        if (
            not _hash(record["sigPubkey"])
            or not isinstance(record["sig"], str)
            or not re.fullmatch(r"[0-9a-f]{128}", record["sig"])
        ):
            return False
        return verify_mutation(
            record["sigPubkey"], record["sig"], _envelope(record["payload"])
        )
    except (ValueError, TypeError, KeyError):
        return False


def _row_matches(record: dict[str, Any], row: dict[str, Any]) -> bool:
    payload = record["payload"]
    plan = payload["plan"]
    return (
        row.get("action") == _ACTION
        and row.get("actor") == plan["actor"]
        and row.get("urn") == f"urn:{plan['org']}:namespace:{plan['namespace']}"
        and row.get("mac") == _digest(_envelope(payload))
        and row.get("hash") is None
        and row.get("seq") == payload["seq"]
        and row.get("prev") == plan["audit_head"]
        and row.get("sig") == record["sig"]
        and row.get("sigPubkey") == record["sigPubkey"]
        and row.get("ts") == payload["issued_at"]
        and _canonical(row.get("details")) == _canonical(record)
    )


def _context_matches(
    root: str,
    data: dict[str, Any],
    org: dict[str, Any] | None,
    record: dict[str, Any],
    *,
    require_org: bool,
) -> list[str]:
    if not _record_valid(record):
        return ["audit-baseline signature or payload is invalid"]
    payload, header = record["payload"], data["manifest"]
    crypto = header.get("cryptoVersion")
    if (
        type(header.get("version")) is not int
        or header["version"] != 1
        or (
            crypto is not None and (type(crypto) is not int or crypto != CRYPTO_VERSION)
        )
    ):
        return [
            "unsupported namespace or crypto version for audit-baseline verification"
        ]
    plan = payload["plan"]
    if any(
        plan[field] != header[key]
        for field, key in (
            ("org", "org"),
            ("namespace", "namespace"),
            ("root_mac", "rootMac"),
        )
    ):
        return ["audit-baseline receipt belongs to another namespace"]
    if require_org and org is None:
        return ["audit-baseline verification requires --org-yaml"]
    if org is not None and (
        org.get("organization", {}).get("id") != plan["org"]
        or not key_valid_at(
            org, plan["actor"], record["sigPubkey"], payload["issued_at"]
        )
    ):
        return [
            "audit-baseline signer is not a declared valid actor key at adoption time"
        ]
    lines, rows = _audit_state(root)
    count = plan["audit_count"]
    if (
        len(rows) < count + 1
        or _digest(b"".join(lines[:count])) != plan["audit_digest"]
        or _digest(lines[count - 1]) != plan["audit_head"]
    ):
        return ["audit-baseline legacy prefix changed or is missing"]
    if not _row_matches(record, rows[count]):
        return ["audit-baseline receipt does not match its durable audit entry"]
    if sum(row.get("action") == _ACTION for row in rows) != 1:
        return ["duplicate audit-baseline entries require separate review"]
    return []


def baseline_issues(
    root: str,
    data: dict[str, Any],
    org: dict[str, Any] | None = None,
    *,
    require_org: bool = False,
) -> list[str]:
    """Verify adoption evidence; ordinary namespaces keep their existing behavior."""
    if not isinstance(data, dict) or not isinstance(data.get("manifest"), dict):
        return ["invalid manifest mapping for audit-baseline verification"]
    record = data["manifest"].get("auditBaseline")
    if record is None:
        try:
            raw = _raw(root)
        except OSError as exc:
            return [f"audit-baseline inspection failed: {exc}"]
        for line in raw.splitlines():
            try:
                row = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue  # Existing audit verification reports malformed old logs.
            if isinstance(row, dict) and row.get("action") == _ACTION:
                if data["manifest"].get("auditSeq") is None:
                    return [
                        "audit-baseline entry is not committed; retry its reviewed adoption plan"
                    ]
                return ["audit-baseline receipt is missing from the committed manifest"]
        return []
    try:
        problems = _context_matches(root, data, org, record, require_org=require_org)
        if problems:
            return problems
        plan, header = record["payload"]["plan"], data["manifest"]
        lines, _rows = _audit_state(root)
        count = header.get("auditSeq")
        seq = header.get("headSeq")
        if (
            type(count) is not int
            or count < plan["audit_count"] + 1
            or count > len(lines)
        ):
            return ["audit-baseline checkpoint count is inconsistent"]
        if header.get("auditHead") != _digest(lines[count - 1]):
            return ["audit-baseline committed audit head does not match its bytes"]
        if type(seq) is not int or seq < record["payload"]["seq"]:
            return ["audit-baseline mutation sequence is inconsistent"]
        return []
    except (ValueError, TypeError, KeyError, OSError) as exc:
        return [f"invalid audit-baseline evidence: {exc}"]


def signing_request(
    plan: dict[str, Any], reason: str, issued_at: str
) -> dict[str, Any]:
    """Prepare exact public signing input; this is not authority to sign."""
    _validate_plan(plan)
    payload = {
        "version": 1,
        "action": _ACTION,
        "plan": plan,
        "reason": reason,
        "issued_at": issued_at,
        "seq": plan.get("next_seq"),
    }
    _envelope(payload)
    return json.loads(_canonical(payload))


def prepare_signing_request(root, data, org, actor, plan, reason):
    """Recheck a reviewed snapshot before producing a fixed-action request."""
    _validate_plan(plan)
    fresh = checkpoint_plan(root, data, org, actor)
    if _canonical(fresh) != _canonical(plan):
        raise ValueError("stale checkpoint signing plan")
    return signing_request(fresh, reason, _now_iso())


def _external_record(record, plan, reason, org, actor):
    record = json.loads(_canonical(record))
    if not _record_valid(record):
        raise ValueError("invalid external checkpoint signature")
    payload = record["payload"]
    if (
        _canonical(payload["plan"]) != _canonical(plan)
        or payload["reason"] != reason
        or payload["plan"]["actor"] != actor
    ):
        raise ValueError("external checkpoint signature does not match the request")
    if not key_valid_now(org, actor, record["sigPubkey"]) or not key_valid_at(
        org, actor, record["sigPubkey"], payload["issued_at"]
    ):
        raise ValueError("external checkpoint signer is not a valid actor key")
    return record


def adopt_checkpoint(
    service, *, plan: dict[str, Any], reason: str, signed_record=None
) -> dict[str, Any]:
    """Adopt one reviewed prefix under the native lock; never truncate the log."""
    try:
        plan = json.loads(_canonical(plan))
        _validate_plan(plan)
        reason = reason.strip() if isinstance(reason, str) else reason
        if not isinstance(reason, str) or not reason or len(reason) > 1024:
            raise ValueError(
                "a non-empty review reason of at most 1024 characters is required"
            )
        path = os.path.join(service.root, MANIFEST_FILENAME)
        with manifest_lock(path):
            service.org = service._load_org(service.org_yaml_path)
            service._require_declared_actor(service.actor_id)
            service._require_namespace_admin()
            service._bind_key_to_actor()
            if signed_record is not None and service.nsec:
                raise ValueError("choose local signing or an external signed record")
            if not service.nsec and signed_record is None:
                raise DocumentError(
                    "denied: adopting an audit checkpoint requires the actor signing key"
                )
            service.policy_hash = policy_hash(service.org)
            supplied = (
                _external_record(
                    signed_record, plan, reason, service.org, service.actor_id
                )
                if signed_record is not None
                else None
            )
            data = load(path)
            existing = data["manifest"].get("auditBaseline")
            if existing is not None:
                if supplied is not None and _canonical(supplied) != _canonical(
                    existing
                ):
                    raise ValueError("external record differs from committed evidence")
                problems = baseline_issues(
                    service.root, data, service.org, require_org=True
                )
                if problems:
                    raise ValueError("; ".join(problems))
                if (
                    _canonical(existing["payload"]["plan"]) != _canonical(plan)
                    or existing["payload"]["reason"] != reason
                    or plan["actor"] != service.actor_id
                ):
                    raise ValueError(
                        "namespace already adopted a different reviewed checkpoint"
                    )
                return {"unchanged": True, "seq": existing["payload"]["seq"]}
            lines, rows = _audit_state(service.root)
            pending = (
                len(rows) == plan["audit_count"] + 1
                and rows[-1].get("action") == _ACTION
            )
            if pending:
                record = rows[-1].get("details")
                if supplied is not None and _canonical(supplied) != _canonical(record):
                    raise ValueError("external record differs from pending evidence")
                problems = _context_matches(
                    service.root, data, service.org, record, require_org=True
                )
                if problems:
                    raise ValueError("; ".join(problems))
                if (
                    _canonical(record["payload"]["plan"]) != _canonical(plan)
                    or record["payload"]["reason"] != reason
                ):
                    raise ValueError(
                        "pending adoption does not match the reviewed request"
                    )
                # The original manifest must still be exactly the reviewed state.
                if (
                    _digest(_canonical(data)) != plan["manifest_digest"]
                    or service.policy_hash != plan["policy_hash"]
                    or plan["actor"] != service.actor_id
                ):
                    raise ValueError(
                        "stale adoption plan or policy; pending evidence is preserved"
                    )
            else:
                fresh = checkpoint_plan(
                    service.root, data, service.org, service.actor_id
                )
                if _canonical(fresh) != _canonical(plan):
                    raise ValueError(
                        "stale adoption plan; re-review the current namespace and audit"
                    )
                payload = signing_request(fresh, reason, _now_iso())
                envelope = _envelope(payload)
                record = supplied or {
                    "payload": payload,
                    "sig": sign_mutation(service.nsec, envelope),
                    "sigPubkey": pubkey_from_nsec(service.nsec),
                }
                payload = record["payload"]
                if supplied is not None:
                    stamp = datetime.strptime(
                        payload["issued_at"], "%Y-%m-%dT%H:%M:%S%z"
                    )
                    if abs((datetime.now(timezone.utc) - stamp).total_seconds()) > 60:
                        raise ValueError(
                            "external checkpoint signature must be within 60 seconds"
                        )
                if not key_valid_at(
                    service.org,
                    service.actor_id,
                    record["sigPubkey"],
                    payload["issued_at"],
                ):
                    raise ValueError(
                        "signing key is not valid at the adoption timestamp"
                    )
            repo = ManifestRepository(data)
            repo.data["manifest"]["auditBaseline"] = record
            if pending:
                from .manifest import save

                header = repo.data["manifest"]
                header.update(
                    headSeq=record["payload"]["seq"],
                    headMac=plan["structural_head"],
                    auditSeq=len(lines),
                    auditHead=_digest(lines[-1]),
                )
                save(path, repo.data)
            else:
                service._commit_transaction(
                    repo,
                    seq=record["payload"]["seq"],
                    action=_ACTION,
                    urn=f"urn:{plan['org']}:namespace:{plan['namespace']}",
                    mac=_digest(_envelope(record["payload"])),
                    ch=None,
                    sig=record["sig"],
                    sig_pubkey=record["sigPubkey"],
                    head_mac=plan["structural_head"],
                    audit_details=record,
                    audit_ts=record["payload"]["issued_at"],
                )
            return {
                "unchanged": False,
                "resumed": pending,
                "seq": record["payload"]["seq"],
                "preserved_entries": plan["audit_count"],
            }
    except (ValueError, TypeError, KeyError, OSError) as exc:
        raise DocumentError(
            f"audit checkpoint adoption refused or interrupted: {exc}"
        ) from exc
