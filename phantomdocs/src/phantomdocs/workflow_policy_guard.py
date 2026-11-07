"""Experimental cooperating-writer lock; never deploy without integration.

This lock protects a policy only if *every* process that can replace or edit it
acquires the exclusive lock. Privileged manual edits are not prevented.
"""

import os
import stat
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def policy_guard(lock_path, *, exclusive):
    import fcntl

    # Never create or replace the lock: that can split the lock domain. Each
    # parent must also be protected so an untrusted user cannot replace it.
    path = Path(lock_path)
    if not path.is_absolute() or ".." in path.parts or path.name in ("", "."):
        raise ValueError("policy lock path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        for component in path.parts[1:-1]:
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("policy lock parent is not protected")
            next_fd = os.open(component, flags, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("policy lock parent is not protected")
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
                or info.st_nlink != 1
            ):
                raise ValueError("policy lock is not protected")
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                if not exclusive:
                    try:
                        os.stat(
                            path.name + ".pending",
                            dir_fd=directory,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        raise ValueError("policy publication requires recovery")
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    finally:
        os.close(directory)
