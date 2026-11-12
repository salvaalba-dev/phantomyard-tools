"""Systemd transaction adapter for an explicitly configured viewer.

This adapter is not an installer or an agent provisioner. The caller must
configure a launch guard and per-request authorization before using it.
"""

import hashlib
import os
import re
import secrets
import subprocess  # nosec B404
import time
from contextlib import ExitStack, contextmanager
from pathlib import PurePosixPath

from phantomdocs.view_agent_journal import (
    clear_journal,
    read_journal,
    write_committed,
    write_journal,
)
from phantomdocs.workflow_admission_config import _read_protected
from phantomdocs.workflow_policy_guard import policy_guard
from phantomdocs.workflow_protected_paths import open_protected_file, protected_parent


class SystemdRouteHost:
    """Connect the transaction engine to protected files and one systemd unit."""

    def __init__(
        self,
        *,
        org,
        config,
        journal,
        committed,
        policy_lock,
        transaction_lock,
        unit,
        validate,
        health,
        readiness_seconds=20,
    ):
        if not isinstance(unit, str) or not re.fullmatch(
            r"[A-Za-z0-9_.@-]+\.service", unit
        ):
            raise ValueError("Invalid systemd unit")
        paths = (org, config, journal, committed, policy_lock, transaction_lock)
        if any(
            not isinstance(path, str)
            or not path.startswith("/")
            or str(PurePosixPath(path)) != path
            or ".." in PurePosixPath(path).parts
            or "\x00" in path
            for path in paths
        ):
            raise ValueError("Absolute host paths required")
        if (
            len(set(paths)) != len(paths)
            or not callable(validate)
            or not callable(health)
        ):
            raise ValueError("Distinct paths and trusted callbacks required")
        self.org, self.config, self.journal, self.committed = paths[:4]
        self.policy_lock, self.transaction_lock = paths[4:]
        self.unit, self._validate, self._health = unit, validate, health
        if type(readiness_seconds) is not int or not 1 <= readiness_seconds <= 60:
            raise ValueError("Bounded readiness interval required")
        self.readiness_seconds = readiness_seconds

    @contextmanager
    def lock(self):
        # Take the transaction lock first everywhere this pair is acquired.
        with ExitStack() as stack:
            stack.enter_context(policy_guard(self.transaction_lock, exclusive=True))
            stack.enter_context(policy_guard(self.policy_lock, exclusive=False))
            yield

    def pending(self):
        return read_journal(self.journal)

    def current_revision_is(self, revision):
        return hashlib.sha256(_read_protected(self.org)).hexdigest() == revision

    def authority(self):
        org = _read_protected(self.org)
        return org, hashlib.sha256(org).hexdigest()

    def committed_revision_is(self, revision):
        committed = read_journal(self.committed)
        return (
            committed is not None
            and committed[1] == revision
            and _read_protected(self.config) == committed[0]
        )

    def configuration_is_committed(self, candidate, revision):
        return (
            read_journal(self.committed) == (candidate, revision)
            and _read_protected(self.config) == candidate
        )

    def validate(self, candidate):
        if self._validate(candidate) is False:
            raise ValueError("Viewer configuration rejected")

    def write_journal(self, candidate, revision):
        write_journal(self.journal, candidate, revision)

    def write_committed(self, candidate, revision):
        write_committed(self.committed, candidate, revision)

    def clear_journal(self):
        clear_journal(self.journal)

    def _systemctl(self, action):
        # Fixed systemctl path, internal action and validated service name.
        return subprocess.run(  # nosec B603
            ["/usr/bin/systemctl", "--system", "--no-ask-password", action, self.unit],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )

    def stop(self):
        self._systemctl("stop")

    def start(self):
        self._systemctl("start")

    def healthy(self):
        # Type=simple becomes active before the reader has opened its sockets.
        # Allow a bounded startup interval, without committing an unready reader.
        deadline = time.monotonic() + self.readiness_seconds
        while True:
            if self._healthy_now():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.25, remaining))

    def _healthy_now(self):
        try:
            self._systemctl("is-active")
        except subprocess.CalledProcessError:
            return False
        return self._health() is True

    def replace(self, candidate):
        if (
            not isinstance(candidate, bytes)
            or not candidate
            or len(candidate) > 1024 * 1024
        ):
            raise ValueError("Invalid viewer configuration")
        with protected_parent(self.config) as (directory, name):
            old = open_protected_file(directory, name)
            try:
                metadata = os.fstat(old)
            finally:
                os.close(old)
            temporary = "." + name + "." + secrets.token_hex(16)
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            try:
                os.fchown(fd, 0, metadata.st_gid)
                os.fchmod(fd, metadata.st_mode & 0o777)
                remaining = memoryview(candidate)
                while remaining:
                    count = os.write(fd, remaining)
                    if count <= 0:
                        raise OSError("Short configuration write")
                    remaining = remaining[count:]
                os.fsync(fd)
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
