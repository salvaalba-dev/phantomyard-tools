"""Durable fanout record, owned only by the cooperating policy publisher."""

import hashlib
import json
import os
import re
import secrets
from pathlib import PurePosixPath

from .workflow_admission_config import _json
from .workflow_policy_sync import MAX_BYTES, policy_permissions
from .workflow_protected_paths import protected_parent

KIND = "bridge-policy-fanout-v1"


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def destinations(source, destination, lock_path):
    """Keep the first destination as the bridge snapshot; reject aliases in config."""
    paths = [destination] if isinstance(destination, str) else destination
    if not isinstance(paths, (tuple, list)) or not 1 <= len(paths) <= 64:
        raise ValueError("one to 64 policy destinations required")
    paths = list(paths)
    all_paths = [
        source,
        lock_path,
        lock_path + ".pending",
        lock_path + ".publisher",
        *paths,
    ]
    if any(
        not isinstance(path, str)
        or not path.startswith("/")
        or "\x00" in path
        or ".." in PurePosixPath(path).parts
        or str(PurePosixPath(path)) != path
        for path in all_paths
    ) or len(set(all_paths)) != len(all_paths):
        raise ValueError("distinct canonical protected policy paths required")
    return paths


def read_pending(lock_path):
    try:
        record = _json(lock_path + ".pending")
    except FileNotFoundError:
        return None
    if not isinstance(record, dict):
        raise ValueError("invalid pending publication record")  # noqa: TRY004 - malformed disk input
    return record


def create_pending(lock_path, record):
    """Publish a complete fsynced record without replacing another transaction."""
    payload = json.dumps(record, sort_keys=True).encode("utf-8")
    if len(payload) > MAX_BYTES:
        raise ValueError("policy publication record is too large")
    with protected_parent(lock_path) as (directory, name):
        temporary = ".policy-fanout-" + secrets.token_hex(16)
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        try:
            view = memoryview(payload)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short publication record write")
                view = view[count:]
            os.fsync(fd)
            # The caller holds the exclusive policy lock. Publish by rename,
            # not link/unlink: a crash must not leave a two-link pending file.
            try:
                os.stat(name + ".pending", dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError("publication already pending")
            os.rename(
                temporary, name + ".pending", src_dir_fd=directory, dst_dir_fd=directory
            )
        finally:
            os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.fsync(directory)


def ensure_independent(paths):
    # A path may be reached via a bind mount even without a hard link. Do not
    # overwrite the source, lock or another destination through such an alias.
    identities = [os.stat(path, follow_symlinks=False) for path in paths]
    if len({(s.st_dev, s.st_ino) for s in identities}) != len(identities):
        raise ValueError("policy files must be independent")


def make_record(
    *,
    source,
    paths,
    payload,
    old,
    unit,
    resolver,
    node,
    active,
    changed,
    commit_witness=False,
):
    record = {
        "kind": KIND,
        "source": source,
        "source_sha256": digest(payload),
        "unit": unit,
        "resolver": resolver,
        "node": node,
        "resume": active,
        "restart": active and changed,
        "destinations": [
            {
                "path": path,
                "old_sha256": digest(data),
                "permissions": policy_permissions(path),
            }
            for path, data in zip(paths, old, strict=True)
        ],
    }
    if commit_witness:
        record["commit_witness"] = True
    return record


def verify_record(
    record, *, source, paths, payload, old, unit, resolver, node, commit_witness=False
):
    """Only retry this exact transaction, content states and permission baseline."""
    fields = {
        "kind",
        "source",
        "source_sha256",
        "unit",
        "resolver",
        "node",
        "resume",
        "restart",
        "destinations",
    }
    if commit_witness:
        fields.add("commit_witness")
    if (
        not isinstance(record, dict)
        or set(record) != fields
        or record["kind"] != KIND
        or record["source"] != source
        or record["source_sha256"] != digest(payload)
        or record["unit"] != unit
        or record["resolver"] != resolver
        or record["node"] != node
        or (commit_witness and record.get("commit_witness") is not True)
        or type(record["resume"]) is not bool
        or type(record["restart"]) is not bool
        or (record["restart"] and not record["resume"])
        or not isinstance(record["destinations"], list)
        or len(record["destinations"]) != len(paths)
    ):
        raise ValueError("pending publication does not match this publisher or source")
    for entry, path, data in zip(record["destinations"], paths, old, strict=True):
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "old_sha256", "permissions"}
            or entry["path"] != path
            or not isinstance(entry["old_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["old_sha256"])
            or digest(data) not in (entry["old_sha256"], record["source_sha256"])
            or policy_permissions(path) != entry["permissions"]
        ):
            raise ValueError("pending destination content or permissions changed")


def clear_pending(lock_path, record):
    """Clear only the record just verified under the exclusive policy lock."""
    if read_pending(lock_path) != record:
        raise ValueError("publication record changed")
    with protected_parent(lock_path) as (directory, name):
        os.unlink(name + ".pending", dir_fd=directory)
        os.fsync(directory)
