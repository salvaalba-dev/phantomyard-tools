"""Create one short-lived initial review grant without replacing policy state."""

import json
import os
import re
import secrets
import time
from pathlib import Path

MAX_LIFETIME_SECONDS = 1800


def create_initial_grant(persona_dir, server, *, lifetime_seconds, now=None):
    """Install an exact MCP grant only when no policy file already exists.

    Run as the persona owner. A complete private temporary file is linked into
    place atomically; an existing or concurrently created policy is never
    replaced. Expiry is enforced by PhantomBot on each broker call.
    """
    if os.name != "posix" or os.getuid() == 0:
        raise ValueError("grant creation requires POSIX")
    if (
        not isinstance(server, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", server)
        or type(lifetime_seconds) is not int
        or not 1 <= lifetime_seconds <= MAX_LIFETIME_SECONDS
    ):
        raise ValueError("invalid review grant")
    path = Path(persona_dir)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute persona directory required")
    current = time.time() if now is None else now
    if not isinstance(current, (int, float)) or not 0 < current < 10**11:
        raise ValueError("invalid clock")
    payload = {
        "version": 1,
        "enabled": True,
        "grants": [
            {
                "id": "phantomdocs-review",
                "kind": "mcp",
                "server": server,
                "tool": "read_review_evidence",
                "arguments": {},
                "expiresAt": int((current + lifetime_seconds) * 1000),
            }
        ],
    }
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    name = None
    try:
        for part in path.parts[1:]:
            info = os.fstat(directory)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise ValueError("unsafe persona path")
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("persona directory must be owner controlled")
        name = ".review-grant-" + secrets.token_hex(16)
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.link(
                name,
                "security-policy.json",
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            os.fsync(directory)
        finally:
            os.unlink(name, dir_fd=directory)
            name = None
    finally:
        if name is not None:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)
