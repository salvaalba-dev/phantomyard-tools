"""Coordinate a collection attempt with readers of its latest snapshot."""

import os
import stat
from contextlib import contextmanager

try:
    import fcntl
except ImportError:
    fcntl = None

LOCK = ".collection.lock"
PENDING = ".collection.pending"


def _private_file(fd, owner_uid):
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise ValueError("unsafe collection state")


@contextmanager
def collection_guard(directory, owner_uid, *, writer):
    """Block new readers during a marked collection attempt.

    The directory must already be opened and validated by the caller. Readers
    never create state. A writer holds an exclusive lock through publication;
    its pending marker survives errors and process termination after it is
    created. The caller must separately handle failures before marker creation
    and failures while clearing or syncing it.
    """
    if fcntl is None:
        raise ValueError("collection coordination requires POSIX locks")
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if writer:
        flags |= os.O_CREAT
    fd = os.open(LOCK, flags, 0o600, dir_fd=directory)
    try:
        _private_file(fd, owner_uid)
        fcntl.flock(fd, (fcntl.LOCK_EX if writer else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        if writer:
            marker = os.open(
                PENDING,
                os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            try:
                _private_file(marker, owner_uid)
                os.fsync(marker)
                os.fsync(directory)
            finally:
                os.close(marker)
        else:
            try:
                os.stat(PENDING, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("collection is incomplete")
        yield
        if writer:
            os.unlink(PENDING, dir_fd=directory)
            os.fsync(directory)
    finally:
        os.close(fd)
