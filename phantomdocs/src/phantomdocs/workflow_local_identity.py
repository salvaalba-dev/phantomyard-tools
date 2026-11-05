"""Resolve a local service actor from a protected, administrator-owned map.

This establishes only a local process identity, not the identity of a remote
sender. All code running as a mapped account is trusted as that account.
"""

import json
import os
import re
import socket
import stat
import struct
import sys
from pathlib import Path

from .workflows import WorkflowError

MAX_MAP_BYTES = 16384


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkflowError("duplicate local identity mapping")
        result[key] = value
    return result


def resolve_local_actor(path):
    """Resolve the effective UID using an administrator-controlled mapping.

    Linux only. Directory traversal uses open file descriptors without following
    symlinks; every directory and the file must be root-owned and not writable by
    group or others. Root itself cannot act as a mapped service identity.
    """
    if sys.platform != "linux" or not hasattr(os, "geteuid"):
        raise WorkflowError("local identity requires Linux effective UID support")
    return _resolve_actor_uid(path, os.geteuid())


def resolve_peer_actor(path, connection):
    """Resolve the kernel-authenticated peer of a connected Unix stream socket.

    The peer UID represents the local service account, not a remote human.
    The caller must create and protect the listening socket separately.
    """
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise WorkflowError("peer identity requires Linux Unix sockets")
    try:
        if (
            connection.family != socket.AF_UNIX
            or connection.type & 0xF != socket.SOCK_STREAM
        ):
            raise WorkflowError("peer identity requires a Unix stream socket")
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, _gid = struct.unpack("3i", raw)
    except (AttributeError, OSError, TypeError, struct.error) as exc:
        raise WorkflowError("cannot read kernel peer credentials") from exc
    if pid <= 0:
        raise WorkflowError("invalid kernel peer credentials")
    return _resolve_actor_uid(path, uid)


def _resolve_actor_uid(path, uid):
    if type(uid) is not int or uid < 0:
        raise WorkflowError("invalid local account identity")
    if uid == 0:
        raise WorkflowError("root cannot be a local workflow actor")
    raw_path = os.fspath(path)
    p = Path(raw_path)
    if not p.is_absolute() or ".." in p.parts or p.name in ("", "."):
        raise WorkflowError("local identity map requires an absolute safe path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", directory_flags)
    try:
        for component in p.parts[1:-1]:
            info = os.fstat(fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise WorkflowError("local identity map directory is not protected")
            next_fd = os.open(component, directory_flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise WorkflowError("local identity map directory is not protected")
        map_fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(map_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o022
                or info.st_size > MAX_MAP_BYTES
            ):
                raise WorkflowError("local identity map is not protected")
            with os.fdopen(map_fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_MAP_BYTES + 1)
        finally:
            os.close(map_fd)
    finally:
        os.close(fd)
    if len(raw) > MAX_MAP_BYTES:
        raise WorkflowError("local identity map is too large")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, ValueError) as exc:
        raise WorkflowError("invalid local identity map") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "actors"}
        or type(document["version"]) is not int
        or document["version"] != 1
        or not isinstance(document["actors"], dict)
    ):
        raise WorkflowError("invalid local identity map")
    for key, actor in document["actors"].items():
        if (
            not isinstance(key, str)
            or not re.fullmatch(r"[1-9][0-9]{0,9}", key)
            or not isinstance(actor, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", actor)
        ):
            raise WorkflowError("invalid local identity entry")
    actor = document["actors"].get(str(uid))
    if actor is None:
        raise WorkflowError("local account is not mapped to an actor")
    return actor
