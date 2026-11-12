"""Durable, root-controlled journal for a viewer route transaction.

The caller must hold the organization lock and a separate exclusive transaction
lock, and must configure a viewer startup guard before enabling this journal.
"""

import base64
import json
import os
import secrets

from phantomdocs.workflow_protected_paths import open_protected_file, protected_parent

MAX_CANDIDATE = 1024 * 1024


def _encode(candidate, revision):
    if not isinstance(candidate, bytes) or not 0 < len(candidate) <= MAX_CANDIDATE:
        raise ValueError("Invalid viewer candidate")
    if not isinstance(revision, str) or not revision or len(revision) > 256:
        raise ValueError("Invalid authority revision")
    return json.dumps(
        {
            "version": 1,
            "candidate": base64.b64encode(candidate).decode("ascii"),
            "revision": revision,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _decode(data):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate journal field")
            obj[key] = value
        return obj

    try:
        obj = json.loads(data, object_pairs_hook=unique)
        if not isinstance(obj, dict) or set(obj) != {
            "version",
            "candidate",
            "revision",
        }:
            raise ValueError("Invalid journal fields")
        if type(obj["version"]) is not int or obj["version"] != 1:
            raise ValueError("Unsupported journal version")
        if not isinstance(obj["candidate"], str):
            raise TypeError("Invalid candidate")
        candidate = base64.b64decode(obj["candidate"], validate=True)
        _encode(candidate, obj["revision"])
        return candidate, obj["revision"]
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("Invalid viewer journal") from exc


def write_journal(path, candidate, revision):
    """Create and sync a journal; refuse to overwrite an existing one."""
    payload = _encode(candidate, revision)
    with protected_parent(path) as (directory, name):
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
                    raise OSError("Short journal write")
                view = view[count:]
            os.fsync(fd)
            os.fsync(directory)
        finally:
            os.close(fd)


def read_journal(path):
    """Return the pending change or None; malformed files fail closed."""
    with protected_parent(path) as (directory, name):
        try:
            fd = open_protected_file(directory, name)
        except FileNotFoundError:
            return None
        try:
            chunks = []
            remaining = MAX_CANDIDATE * 2
            while remaining:
                data = os.read(fd, min(remaining, 65536))
                if not data:
                    break
                chunks.append(data)
                remaining -= len(data)
            if remaining == 0:
                raise ValueError("Oversized viewer journal")
            return _decode(b"".join(chunks))
        finally:
            os.close(fd)


def clear_journal(path):
    """Remove and sync a previously validated journal under the host lock."""
    with protected_parent(path) as (directory, name):
        fd = open_protected_file(directory, name)
        try:
            current = os.fstat(fd)
            entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (entry.st_dev, entry.st_ino):
                raise ValueError("Viewer journal changed")
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(fd)


def write_committed(path, candidate, revision):
    """Atomically persist an authority binding before clearing the journal.

    The caller must hold the transaction lock, and the directory must be
    root-controlled. A pending journal remains authoritative on failure.
    """
    payload = _encode(candidate, revision)
    with protected_parent(path) as (directory, name):
        try:
            existing = open_protected_file(directory, name)
        except FileNotFoundError:
            pass
        else:
            os.close(existing)
        temporary = "." + name + "." + secrets.token_hex(16)
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
                    raise OSError("Short committed record write")
                view = view[count:]
            os.fsync(fd)
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
