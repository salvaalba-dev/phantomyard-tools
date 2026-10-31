"""Read an operator-controlled receipt relative to an already trusted directory.

The caller must securely open and authenticate the directory and its ancestry.
Private filesystem custody limits who can alter a receipt; it does not prove who
originally made the claims or authorize a document operation.
"""

import json
import os
import stat
from contextlib import contextmanager

from .workflows import WorkflowError

MAX_RECEIPT_BYTES = 64 * 1024


@contextmanager
def trusted_receipt_directory(path):
    """Open an absolute directory without following untrusted path components.

    Ancestors must be owned by root or the current account and not writable by
    others; a root-owned sticky directory (such as /var/tmp) is permitted.
    The final directory must be private and owned by the current account.
    """
    if os.name != "posix" or not all(
        hasattr(os, field) for field in ("O_NOFOLLOW", "O_DIRECTORY", "geteuid")
    ):
        raise WorkflowError("private receipt reading requires POSIX")
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        raise WorkflowError("receipt directory must be an absolute path")
    parts = path.split("/")[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise WorkflowError("invalid receipt directory path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = None
    try:
        current = os.open("/", flags)
        for index, part in enumerate(parts):
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
            info = os.fstat(current)
            mode = stat.S_IMODE(info.st_mode)
            if index == len(parts) - 1:
                if info.st_uid != os.geteuid() or mode & 0o077:
                    raise WorkflowError(
                        "receipt directory must be private and owned by caller"
                    )
            elif info.st_uid not in {0, os.geteuid()} or (
                mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX)
            ):
                raise WorkflowError("untrusted receipt directory ancestor")
        yield current
    except OSError as error:
        raise WorkflowError("cannot safely open receipt directory") from error
    finally:
        if current is not None:
            os.close(current)


def read_receipt(directory_fd, name):
    """Read one bounded JSON object using a pre-opened trusted POSIX directory."""
    if os.name != "posix" or not all(
        hasattr(os, field) for field in ("O_NOFOLLOW", "O_DIRECTORY", "geteuid")
    ):
        raise WorkflowError("private receipt reading requires POSIX")
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
    ):
        raise WorkflowError("receipt name must be a single path component")
    try:
        directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) & 0o077
        ):
            raise WorkflowError("receipt directory must be private and owned by caller")
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
        )
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_size > MAX_RECEIPT_BYTES
            ):
                raise WorkflowError("receipt must be a private owned regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_RECEIPT_BYTES + 1)
            after = os.fstat(fd)
            if len(raw) > MAX_RECEIPT_BYTES or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise WorkflowError("receipt changed during reading")
        finally:
            os.close(fd)
    except OSError as error:
        raise WorkflowError("cannot safely read receipt") from error

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise WorkflowError("duplicate receipt field")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("non-finite value")
            ),
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise WorkflowError("invalid receipt JSON") from error
    if not isinstance(value, dict):
        raise WorkflowError("receipt must be an object")
    return value
