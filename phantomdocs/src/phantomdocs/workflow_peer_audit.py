"""Bounded, filtered audit views for authenticated local document readers."""

import json
import os
import re
import stat
from collections import deque

from .access import can_read
from .manifest import node_by_mac, node_by_urn

MAX_AUDIT_BYTES = 8 * 1024 * 1024
MAX_AUDIT_LIMIT = 100
_ACTIONS = {"add", "version", "mkdir", "rollback", "tag"}
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate audit field")
        result[key] = value
    return result


def load_audit_file(path):
    """Read a bounded regular file without following a final symlink."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("protected audit access requires no-follow support")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_AUDIT_BYTES:
            raise ValueError("audit file unavailable")
        with os.fdopen(fd, "rb", closefd=False) as file:
            raw = file.read(MAX_AUDIT_BYTES + 1)
        after = os.fstat(fd)
        attrs = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) > MAX_AUDIT_BYTES or any(
            getattr(before, name) != getattr(after, name) for name in attrs
        ):
            raise ValueError("audit file changed")
        return raw
    finally:
        os.close(fd)


def filtered_audit(raw, *, org, actor, manifest, limit):
    """Return a redacted view, not a complete or chain-verifiable audit log."""
    if type(limit) is not int or not 1 <= limit <= MAX_AUDIT_LIMIT:
        raise ValueError("invalid audit limit")
    if not isinstance(raw, bytes) or len(raw) > MAX_AUDIT_BYTES:
        raise ValueError("invalid audit snapshot")
    if raw and not raw.endswith(b"\n"):
        raise ValueError("incomplete audit snapshot")
    known_actors = {a.get("id") for a in org.get("actors", []) if isinstance(a, dict)}
    results = deque(maxlen=limit)
    for line in raw.splitlines():
        if not line.strip():
            continue
        entry = json.loads(
            line,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("invalid constant")
            ),
        )
        if not isinstance(entry, dict):
            raise TypeError("invalid audit entry")
        action, who, ts = entry.get("action"), entry.get("actor"), entry.get("ts")
        urn, mac = entry.get("urn"), entry.get("mac")
        if (
            action not in _ACTIONS
            or not isinstance(who, str)
            or who not in known_actors
            or not isinstance(ts, str)
            or _TS.fullmatch(ts) is None
            or not isinstance(urn, str)
            or not urn.isprintable()
            or not isinstance(mac, str)
        ):
            continue
        node = node_by_mac(manifest, mac)
        current = node_by_urn(manifest, urn)
        if (
            node is None
            or current is None
            or node["urn"] != urn
            or not can_read(org, actor, node["category"])
            or not can_read(org, actor, current["category"])
        ):
            continue
        results.append(
            {"ts": ts, "actor": who, "action": action, "urn": urn, "mac": mac}
        )
    return list(results)
