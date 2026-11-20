"""Optional committed source receipt inside the existing, never-replaced lock.

Contains only a source path and SHA-256, never model/identity data. Writers must
hold the common exclusive lock; readers retain a shared lock through delivery.
"""

import json
import os
from contextlib import contextmanager

from .workflow_policy_fanout import digest
from .workflow_policy_guard import policy_guard
from .workflow_policy_sync import _permissions
from .workflow_protected_paths import open_protected_file, protected_parent

KIND = "phantomorg-committed-source-v1"
MAX_RECEIPT = 8192


def receipt(source, payload):
    value = {"kind": KIND, "source": source, "sha256": digest(payload)}
    if len(json.dumps(value, sort_keys=True).encode()) > MAX_RECEIPT:
        raise ValueError("committed source receipt exceeds limit")
    return value


def _encoded(source, payload):
    raw = json.dumps(receipt(source, payload), sort_keys=True).encode()
    if len(raw) > MAX_RECEIPT:
        raise ValueError("committed source receipt exceeds limit")
    return raw


def _decode(raw, source):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate receipt key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
        if (
            len(raw) > MAX_RECEIPT
            or not isinstance(value, dict)
            or set(value) != {"kind", "source", "sha256"}
            or value["kind"] != KIND
            or value["source"] != source
            or not isinstance(value["sha256"], str)
            or len(value["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in value["sha256"])
        ):
            raise ValueError("invalid committed receipt")
        return value
    except (ValueError, UnicodeError, TypeError):
        raise ValueError("committed source is unavailable") from None


def inspect_committed_locked(lock_path, source):
    """Fresh writers may bootstrap an empty lock, never adopt foreign contents."""
    with protected_parent(lock_path) as (directory, name):
        fd = open_protected_file(directory, name)
        try:
            raw = os.read(fd, MAX_RECEIPT + 1)
        finally:
            os.close(fd)
    return _decode(raw, source) if raw else None


def write_committed_locked(lock_path, source, payload):
    """Caller holds EX. Preserve inode and every existing permission attribute."""
    raw = _encoded(source, payload)
    with protected_parent(lock_path) as (directory, name):
        checked = open_protected_file(directory, name)
        try:
            baseline = _permissions(checked)
            identity = os.fstat(checked)
            fd = os.open(
                name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
            )
            try:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) != (
                    identity.st_dev,
                    identity.st_ino,
                ):
                    raise ValueError("policy lock changed")
                old = os.read(fd, MAX_RECEIPT + 1)
                if old == raw:
                    return
                os.lseek(fd, 0, os.SEEK_SET)
                view = memoryview(raw)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("short committed source write")
                    view = view[count:]
                os.ftruncate(fd, len(raw))
                os.fsync(fd)
                named = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (named.st_dev, named.st_ino) != (
                    identity.st_dev,
                    identity.st_ino,
                ) or _permissions(fd) != baseline:
                    raise ValueError("policy lock metadata changed")
            finally:
                os.close(fd)
        finally:
            os.close(checked)


@contextmanager
def committed_guard(lock_path, source):
    """No creation, recovery, source access or permission changes are performed."""
    with policy_guard(lock_path, exclusive=False, timeout=2):
        with protected_parent(lock_path, search_only=True) as (directory, name):
            fd = open_protected_file(directory, name)
            try:
                raw = os.read(fd, MAX_RECEIPT + 1)
            finally:
                os.close(fd)
        value = _decode(raw, source)
        yield value
