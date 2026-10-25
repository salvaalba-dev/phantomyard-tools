"""One-time local migration of unsigned legacy checkpoints; never a service."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path

from phantomdocs import audit, manifest
from phantomdocs.access import can_administer_namespace, load_org, policy_hash
from phantomdocs.audit_baseline import (
    _audit_state,
    _canonical,
    _validate_plan,
    checkpoint_plan,
    read_checkpoint_plan,
)

ACTION = "migrate-legacy-checkpoint"
SCHEMA = "phantomdocs.local-checkpoint-migration/v1"


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _unsigned(data, rows):
    header = data["manifest"]
    if (
        any(
            header.get(key) is not None
            for key in (
                "auditBaseline",
                "signedRootMac",
                "sealPubkey",
            )
        )
        or any(
            header.get(key)
            for key in (
                "requireSignatures",
                "sealKeys",
                "seals",
                "revocations",
                "profileTransition",
            )
        )
        or any(n.get("sig") or n.get("sigPubkey") for n in data["nodes"])
    ):
        raise ValueError(
            "local migration only supports unsigned, unsealed legacy stores"
        )
    if any(row.get("sig") or row.get("sigPubkey") for row in rows):
        raise ValueError("signed audit history requires the native signed migration")


def review(root, org_path, actor):
    """Read-only plan using native schema, authority and source-state guards."""
    data = manifest.load(str(Path(root) / manifest.MANIFEST_FILENAME))
    _lines, rows = _audit_state(root)
    _unsigned(data, rows)
    if any(row.get("action") == ACTION for row in rows):
        raise ValueError(
            "migration already attempted; retry the original reviewed plan"
        )
    return checkpoint_plan(root, data, load_org(org_path), actor)


def _receipt_valid(receipt):
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema",
        "mode",
        "plan",
        "reason",
        "timestamp",
        "operator_uid",
    }:
        raise ValueError("invalid local migration receipt")
    if receipt["schema"] != SCHEMA or receipt["mode"] != "unsigned-local-admin":
        raise ValueError("unsupported local migration receipt")
    _validate_plan(receipt["plan"])
    reason = receipt["reason"]
    if (
        not isinstance(reason, str)
        or not reason
        or reason != reason.strip()
        or len(reason) > 1024
    ):
        raise ValueError("invalid local migration reason")
    uid = receipt["operator_uid"]
    if uid is not None and (type(uid) is not int or uid < 0):
        raise ValueError("invalid local operator uid")
    stamp = receipt["timestamp"]
    if not isinstance(stamp, str) or not stamp.endswith("Z"):
        raise ValueError("invalid local migration timestamp")
    datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S%z")


def _matches(row, receipt):
    plan = receipt["plan"]
    return (
        row.get("action") == ACTION
        and row.get("actor") == plan["actor"]
        and row.get("urn") == f"urn:{plan['org']}:namespace:{plan['namespace']}"
        and row.get("mac") == _hash(_canonical(receipt))
        and row.get("hash") is None
        and type(row.get("seq")) is int
        and row["seq"] == plan["next_seq"]
        and row.get("prev") == plan["audit_head"]
        and row.get("ts") == receipt["timestamp"]
        and row.get("sig") is None
        and row.get("sigPubkey") is None
        and _canonical(row.get("details")) == _canonical(receipt)
    )


def apply(root, org_path, actor, plan, reason):
    """Preserve old bytes, append one unsigned receipt, then commit native anchors."""
    plan = json.loads(_canonical(plan))
    _validate_plan(plan)
    if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 1024:
        raise ValueError("a non-empty reason of at most 1024 characters is required")
    reason = reason.strip()
    path = str(Path(root) / manifest.MANIFEST_FILENAME)
    with manifest.manifest_lock(path):
        org = load_org(org_path)
        if not can_administer_namespace(org, actor) or actor != plan["actor"]:
            raise ValueError("denied: current native namespace administrator required")
        if org["organization"]["id"] != plan["org"]:
            raise ValueError("organization does not match reviewed namespace")
        data = manifest.load(path)
        issues = manifest.structural_issues(data) + manifest.mutation_sequence_issues(
            data
        )
        if issues:
            raise ValueError(
                "namespace structure requires review: " + "; ".join(issues)
            )
        lines, rows = _audit_state(root)
        _unsigned(data, rows)
        header = data["manifest"]
        if any(
            header[key] != plan[field]
            for key, field in (
                ("org", "org"),
                ("namespace", "namespace"),
                ("rootMac", "root_mac"),
            )
        ):
            raise ValueError("namespace identity differs from reviewed plan")
        matches = [i for i, row in enumerate(rows) if row.get("action") == ACTION]
        count = plan["audit_count"]
        if matches:
            if matches != [count]:
                raise ValueError(
                    "unexpected migration entries; preserve history for review"
                )
            row = rows[count]
            receipt = row.get("details")
            _receipt_valid(receipt)
            if (
                _canonical(receipt["plan"]) != _canonical(plan)
                or receipt["reason"] != reason
                or not _matches(row, receipt)
            ):
                raise ValueError("migration receipt differs from the reviewed request")
            if (
                _hash(b"".join(lines[:count])) != plan["audit_digest"]
                or _hash(lines[count - 1]) != plan["audit_head"]
            ):
                raise ValueError("original audit prefix differs from reviewed history")
            if (
                header.get("auditSeq") is not None
                or header.get("auditHead") is not None
            ):
                committed = header.get("auditSeq")
                if (
                    type(committed) is not int
                    or not count + 1 <= committed <= len(lines)
                    or header.get("auditHead") != _hash(lines[committed - 1])
                    or type(header.get("headSeq")) is not int
                    or header["headSeq"] != audit.max_seq(root)
                    or header["headSeq"] < plan["next_seq"]
                ):
                    raise ValueError(
                        "committed checkpoint is inconsistent; refusing repair"
                    )
                return {"unchanged": True, "signed": False, "seq": plan["next_seq"]}
            if len(lines) != count + 1:
                raise ValueError("unknown pending tail; preserve history for review")
            if (
                _hash(_canonical(data)) != plan["manifest_digest"]
                or policy_hash(org) != plan["policy_hash"]
            ):
                raise ValueError("pending migration source or policy changed")
            head = _hash(lines[-1])
            resumed = True
        else:
            fresh = checkpoint_plan(root, data, org, actor)
            if _canonical(fresh) != _canonical(plan):
                raise ValueError("stale migration plan; review current sources")
            receipt = {
                "schema": SCHEMA,
                "mode": "unsigned-local-admin",
                "plan": plan,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "operator_uid": os.geteuid() if hasattr(os, "geteuid") else None,
            }
            _receipt_valid(receipt)
            head = audit.append(
                root,
                actor,
                ACTION,
                f"urn:{plan['org']}:namespace:{plan['namespace']}",
                _hash(_canonical(receipt)),
                None,
                seq=plan["next_seq"],
                details=receipt,
                timestamp=receipt["timestamp"],
            )
            resumed = False
        header.update(
            headSeq=plan["next_seq"],
            headMac=plan["structural_head"],
            auditSeq=count + 1,
            auditHead=head,
        )
        manifest.save(path, data)
        return {
            "unchanged": False,
            "resumed": resumed,
            "signed": False,
            "preserved_entries": count,
            "seq": plan["next_seq"],
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("plan", "apply"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--org-yaml", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--review")
    parser.add_argument("--reason")
    args = parser.parse_args(argv)
    try:
        if args.operation == "plan":
            result = review(args.root, args.org_yaml, args.actor)
        else:
            if not args.review or not args.reason:
                parser.error("apply requires --review and --reason")
            result = apply(
                args.root,
                args.org_yaml,
                args.actor,
                read_checkpoint_plan(args.review),
                args.reason,
            )
    except (ValueError, OSError) as exc:
        parser.exit(1, f"refusing local migration: {exc}\n")
    print(json.dumps(result, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
