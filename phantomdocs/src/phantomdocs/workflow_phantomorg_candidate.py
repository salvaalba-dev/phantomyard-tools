"""Validate reviewed source snapshots through the owning PhantomOrg package."""

import base64
import re
from contextlib import contextmanager

from . import workflow_policy_fanout as fanout
from .workflow_admission_config import parse_policy
from .workflow_policy_sync import policy_permissions

KIND = "phantomorg-source-fanout-v1"
MAX_CANDIDATE = 2 * 1024 * 1024
EXTRA_FIELDS = {
    "candidate",
    "source_before_sha256",
    "source_permissions",
    "organization",
}


def review_options(
    candidate, expected_source_sha256, candidate_sha256, organization, prestart
):
    if candidate is None:
        if expected_source_sha256 is not None or candidate_sha256 is not None:
            raise ValueError("source review requires a candidate")
        return
    if prestart or not isinstance(organization, str) or not organization:
        raise ValueError(
            "source publication requires an organization and normal orchestration"
        )
    for value in (expected_source_sha256, candidate_sha256):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(
                "source publication requires both reviewed SHA-256 digests"
            )


def validate(payload, organization):
    """No subprocess, persona discovery, compilation or deployment is involved."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_CANDIDATE:
        raise ValueError("invalid PhantomOrg candidate size")
    try:
        from phantomorg.spec.loader import OrgSpecError
        from phantomorg.validator import validate_org_bytes
    except ImportError:
        raise ValueError(
            "install matching PhantomOrg source-publication support"
        ) from None
    try:
        spec, result = validate_org_bytes(payload)
    except (OrgSpecError, ValueError, TypeError, RecursionError):
        raise ValueError("candidate failed PhantomOrg validation") from None
    if not result.ok or spec.organization.id != organization:
        raise ValueError("invalid PhantomOrg candidate or organization mismatch")


def source_identity(payload, organization):
    current = parse_policy(payload).get("organization")
    if not isinstance(current, dict) or current.get("id") != organization:
        raise ValueError("current source organization mismatch")


def make_record(*, source, paths, payload, before, old, organization, **settings):
    record = fanout.make_record(
        source=source, paths=paths, payload=payload, old=old, **settings
    )
    record.update(
        kind=KIND,
        candidate=base64.b64encode(payload).decode("ascii"),
        source_before_sha256=fanout.digest(before),
        source_permissions=policy_permissions(source),
        organization=organization,
    )
    return record


def recover_payload(record, *, source, paths, before, old, organization, **settings):
    # Strip only this schema's explicit extension and let the existing fanout
    # validator enforce its exact field set and configured consumer bindings.
    if (
        not isinstance(record, dict)
        or record.get("kind") != KIND
        or not EXTRA_FIELDS <= set(record)
    ):
        raise ValueError("invalid source publication record")
    try:
        payload = base64.b64decode(record["candidate"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("invalid recorded candidate") from None
    bound_org = record["organization"]
    if (
        not isinstance(bound_org, str)
        or not bound_org
        or (organization is not None and organization != bound_org)
    ):
        raise ValueError("pending source organization mismatch")
    validate(payload, bound_org)
    source_identity(before, bound_org)
    old_hash = record["source_before_sha256"]
    if (
        not isinstance(old_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", old_hash)
        or fanout.digest(before) not in (old_hash, fanout.digest(payload))
        or policy_permissions(source) != record["source_permissions"]
    ):
        raise ValueError("pending source content or permissions changed")
    base = {k: v for k, v in record.items() if k not in EXTRA_FIELDS}
    base["kind"] = fanout.KIND
    fanout.verify_record(
        base, source=source, paths=paths, payload=payload, old=old, **settings
    )
    return payload


@contextmanager
def payload_file(lock_path, payload):
    """Stage journal-pinned bytes in a private disposable file under the lock."""
    import os
    import secrets
    from pathlib import PurePosixPath

    from .workflow_protected_paths import protected_parent

    with protected_parent(lock_path) as (directory, _):
        name = ".phantomorg-payload-" + secrets.token_hex(16)
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        try:
            view = memoryview(payload)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short candidate staging write")
                view = view[count:]
            os.fsync(fd)
            yield str(PurePosixPath(lock_path).parent / name)
        finally:
            os.close(fd)
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
