"""Protected policy synchronization experiment; not an installed service.

This coordinates only cooperating policy writers; it does not prevent a root
operator or an older synchronizer from changing the policy without the lock.
"""

import argparse
import os
import secrets
import stat

import yaml

from .access import validate_org_schema
from .workflow_policy_guard import policy_guard
from .workflow_protected_paths import open_protected_file, protected_parent

MAX_BYTES = 4 * 1024 * 1024


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def synchronize(source, destination, lock_path):
    """Replace a policy only after checking pinned files and preserving ACLs."""
    with policy_guard(lock_path, exclusive=True):  # noqa: SIM117
        with (
            protected_parent(source) as (source_dir, source_name),
            protected_parent(destination) as (dest_dir, dest_name),
        ):
            src = open_protected_file(source_dir, source_name)
            dst = None
            tmp = None
            name = None
            try:
                before = os.fstat(src)
                chunks, remaining = [], MAX_BYTES + 1
                while remaining:
                    part = os.read(src, min(remaining, 65536))
                    if not part:
                        break
                    chunks.append(part)
                    remaining -= len(part)
                payload = b"".join(chunks)
                if (
                    not payload
                    or len(payload) > MAX_BYTES
                    or _identity(os.fstat(src)) != _identity(before)
                ):
                    raise ValueError("invalid or changed source")
                data = yaml.safe_load(payload)
                if not isinstance(data, dict):
                    raise ValueError("invalid organization")  # noqa: TRY004
                validate_org_schema(data)
                dst = open_protected_file(dest_dir, dest_name)
                old = os.fstat(dst)
                if (before.st_dev, before.st_ino) == (old.st_dev, old.st_ino):
                    raise ValueError("source and destination must differ")
                attrs = {key: os.getxattr(dst, key) for key in os.listxattr(dst)}
                name = ".org-trial-" + secrets.token_hex(16)
                tmp = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=dest_dir,
                )
                os.fchown(tmp, old.st_uid, old.st_gid)
                os.fchmod(tmp, stat.S_IMODE(old.st_mode))
                for key in os.listxattr(tmp):
                    os.removexattr(tmp, key)
                for key, value in attrs.items():
                    os.setxattr(tmp, key, value)
                if {key: os.getxattr(tmp, key) for key in os.listxattr(tmp)} != attrs:
                    raise ValueError("extended permissions changed")
                view = memoryview(payload)
                while view:
                    written = os.write(tmp, view)
                    if written <= 0:
                        raise OSError("short policy write")
                    view = view[written:]
                os.fsync(tmp)
                if (
                    _identity(os.fstat(src)) != _identity(before)
                    or _identity(
                        os.stat(source_name, dir_fd=source_dir, follow_symlinks=False)
                    )
                    != _identity(before)
                    or _identity(os.fstat(dst)) != _identity(old)
                    or _identity(
                        os.stat(dest_name, dir_fd=dest_dir, follow_symlinks=False)
                    )
                    != _identity(old)
                ):
                    raise ValueError("policy files changed during synchronization")
                os.replace(name, dest_name, src_dir_fd=dest_dir, dst_dir_fd=dest_dir)
                name = None
                os.fsync(dest_dir)
            finally:
                if tmp is not None:
                    os.close(tmp)
                if name is not None:
                    try:
                        os.unlink(name, dir_fd=dest_dir)
                    except FileNotFoundError:
                        pass
                if dst is not None:
                    os.close(dst)
                os.close(src)


def main():
    """Synchronize administrator-selected paths under a cooperating lock."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--policy-lock", required=True)
    options = parser.parse_args()
    synchronize(options.source, options.destination, options.policy_lock)


if __name__ == "__main__":
    main()
