"""Publish a reviewed policy with a fail-closed interruption marker.

Only cooperating readers and writers are coordinated. Root operators must not
edit the live source directly while a protected peer is running.
"""

import argparse
import hashlib
import os
import re
import stat

from .workflow_admission_config import _read_protected, parse_policy
from .workflow_policy_guard import policy_guard
from .workflow_policy_sync import _synchronize_locked
from .workflow_protected_paths import protected_parent


def _marker(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_nlink != 1
        ):
            raise ValueError("invalid publication marker")
    finally:
        os.close(fd)


def publish(candidate, source, destination, backup, lock_path, expected_sha256):
    """Publish a candidate, preserving a verified independent backup."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_sha256
    ):
        raise ValueError("invalid expected source digest")
    with policy_guard(lock_path, exclusive=True):
        paths = (candidate, source, destination, backup)
        payloads = [_read_protected(path) for path in paths]
        identities = [
            (
                os.stat(path, follow_symlinks=False).st_dev,
                os.stat(path, follow_symlinks=False).st_ino,
            )
            for path in paths
        ]
        if len(set(identities)) != len(paths):
            raise ValueError("policy files must be independent")
        new, old, installed, saved = payloads
        if (
            hashlib.sha256(old).hexdigest() != expected_sha256
            or old != installed
            or old != saved
        ):
            raise ValueError("source, installed policy or backup changed")
        parse_policy(new)
        with protected_parent(lock_path) as (directory, lock_name):
            marker = lock_name + ".pending"
            fd = os.open(
                marker,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
            _synchronize_locked(
                candidate, source, expected_source=new, expected_destination=old
            )
            _synchronize_locked(
                source, destination, expected_source=new, expected_destination=old
            )
            os.unlink(marker, dir_fd=directory)
            os.fsync(directory)


def recover(source, destination, lock_path):
    """Complete an interrupted publication using the authoritative source."""
    with policy_guard(lock_path, exclusive=True):  # noqa: SIM117
        with protected_parent(lock_path) as (directory, lock_name):
            marker = lock_name + ".pending"
            _marker(directory, marker)
            _synchronize_locked(source, destination)
            os.unlink(marker, dir_fd=directory)
            os.fsync(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    change = sub.add_parser("publish")
    for option in (
        "candidate",
        "source",
        "destination",
        "backup",
        "policy-lock",
        "expected-sha256",
    ):
        change.add_argument("--" + option, required=True)
    repair = sub.add_parser("recover")
    for option in ("source", "destination", "policy-lock"):
        repair.add_argument("--" + option, required=True)
    args = vars(parser.parse_args())
    operation = args.pop("operation")
    if operation == "publish":
        publish(**args)
    else:
        recover(**args)


if __name__ == "__main__":
    main()
