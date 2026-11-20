"""Experimental cooperating-writer lock; never deploy without integration.

This lock protects a policy only if *every* process that can replace or edit it
acquires the exclusive lock. Privileged manual edits are not prevented.
"""

import json
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path


class PolicyRecoveryRequired(ValueError):
    """A policy publication was interrupted and must be recovered."""


@contextmanager
def policy_guard(lock_path, *, exclusive, recovering=False, timeout=None):
    """Serialize policy use; only explicit exclusive recovery may bypass pending."""
    if recovering and not exclusive:
        raise ValueError("policy recovery requires an exclusive lock")
    if timeout is not None and (
        type(timeout) not in (int, float) or not 0 < timeout <= 60
    ):
        raise ValueError("invalid policy lock timeout")
    import fcntl

    # Never create or replace the lock: that can split the lock domain. Each
    # parent must also be protected so an untrusted user cannot replace it.
    path = Path(lock_path)
    if not path.is_absolute() or ".." in path.parts or path.name in ("", "."):
        raise ValueError("policy lock path must be absolute")
    # Pin and inspect ancestors without requiring permission to list them.
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
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
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            if timeout is None:
                fcntl.flock(fd, operation)
            else:
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        fcntl.flock(fd, operation | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("policy lock unavailable") from None
                        time.sleep(min(0.01, max(0, deadline - time.monotonic())))
            try:
                # Once installed, the receipt protocol cannot be silently
                # disabled by omitting a CLI flag or invoking an ordinary writer.
                try:
                    receipt = json.loads(os.pread(fd, 8193, 0))
                    committed = (
                        isinstance(receipt, dict)
                        and receipt.get("kind") == "phantomorg-committed-source-v1"
                    )
                except (ValueError, UnicodeError):
                    committed = False
                if exclusive and committed and not recovering:
                    raise PolicyRecoveryRequired("use the committed policy publisher")
                if not recovering:
                    try:
                        os.stat(
                            path.name + ".pending",
                            dir_fd=directory,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        raise PolicyRecoveryRequired(
                            "policy publication requires recovery"
                        )
                yield committed
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    finally:
        os.close(directory)
