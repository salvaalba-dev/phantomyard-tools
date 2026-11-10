"""Read a bounded Drive object with the current agent's Workspace tool.

The supervising broker must launch this worker under the configured agent UID,
with a reviewed tool path and environment. No credential is read by the broker.
"""

import os
import re
import stat
import subprocess
import tempfile

from .view_matrix import MAX_MATRIX_BYTES

_REF = re.compile(r"gdrive://([A-Za-z0-9_-]{10,200})\Z")


def read_workspace(ref, limit, *, workspace, expected_uid, timeout=20):
    """Download one ref in an agent-owned temporary file and return its bytes."""
    match = _REF.fullmatch(ref) if isinstance(ref, str) else None
    if (
        os.name != "posix"
        or type(expected_uid) is not int
        or expected_uid <= 0
        or os.getuid() != expected_uid
        or not isinstance(workspace, str)
        or not workspace.startswith("/")
        or not match
        or type(limit) is not int
        or not 1 <= limit <= MAX_MATRIX_BYTES + 1
        or type(timeout) is not int
        or not 1 <= timeout <= 30
    ):
        raise ValueError("workspace reader unavailable")
    with tempfile.NamedTemporaryFile(prefix="pd-matrix-") as output:
        subprocess.run(
            [workspace, "drive", "download", match.group(1), output.name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=True,
        )
        # Retain the original descriptor: an agent-controlled replacement path
        # cannot make the supervisor read another file through a symlink.
        before = os.fstat(output.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or before.st_size > limit
        ):
            raise ValueError("workspace reader unavailable")
        output.seek(0)
        result = output.read(limit + 1)
        after = os.fstat(output.fileno())
        if (
            len(result) > limit
            or before.st_size != len(result)
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ValueError("workspace reader unavailable")
        return result
