"""Root-controlled file access for a Linux-only, non-production trial."""

import os
import stat
from contextlib import contextmanager


@contextmanager
def protected_parent(path, *, search_only=False):
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        raise ValueError("absolute path required")
    parts = path.split("/")[1:]
    if len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
        raise ValueError("unsafe path")
    # Linux O_PATH needs traversal, not directory listing permission. Writers
    # keep ordinary directory descriptors because they must fsync them.
    access = os.O_PATH if search_only else os.O_RDONLY
    flags = access | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in parts[:-1]:
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("unprotected parent directory")
            next_fd = os.open(
                part,
                flags,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unprotected parent directory")
        yield fd, parts[-1]
    finally:
        os.close(fd)


def open_protected_file(parent_fd, name):
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or info.st_nlink != 1
    ):
        os.close(fd)
        raise ValueError("unprotected file")
    return fd
