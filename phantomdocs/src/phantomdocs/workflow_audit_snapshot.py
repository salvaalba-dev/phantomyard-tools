"""Collect a non-transactional Drive observation for human or agent review."""

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

from .workflow_audit_evidence import MAX_EVIDENCE_BYTES, prepare_evidence
from .workflow_drive_inventory import DriveInboxInventory
from .workflow_drive_reader import DriveArchiveReader
from .workflow_drive_tree import inventory_tree
from .workflows import WorkflowError


def collect_evidence(inventory, reader, *, root_ref, matrix_ref, matrix_prefix):
    if not isinstance(matrix_prefix, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,100}", matrix_prefix
    ):
        raise WorkflowError("invalid matrix prefix")
    tree = inventory_tree(inventory, root_ref)
    identity = (
        matrix_ref.removeprefix("gdrive://")
        if matrix_ref.startswith("gdrive://")
        else ""
    )
    pattern = re.compile(
        re.escape(matrix_prefix) + r"_v([0-9]+)(?:_|\.)", re.IGNORECASE
    )
    candidates = [
        (int(match.group(1)), item)
        for item in tree["items"]
        if (match := pattern.match(item.get("name", "")))
    ]
    selected = [
        (version, item) for version, item in candidates if item["id"] == identity
    ]
    if (
        len(selected) != 1
        or sum(version == selected[0][0] for version, _ in candidates) != 1
    ):
        raise WorkflowError("current matrix identity is missing or ambiguous")
    if selected[0][0] != max(version for version, _ in candidates):
        raise WorkflowError("a newer matrix is present")
    before = reader.refresh_metadata(matrix_ref)
    observed = selected[0][1]
    if any(
        before.get(field) != observed.get(field)
        for field in ("id", "parents", "size", "version", "md5Checksum")
    ):
        raise WorkflowError("matrix changed after inventory")
    content, _ = reader.read_reference(matrix_ref)
    try:
        matrix = content.file.read()
    finally:
        content.close()
    after = reader.refresh_metadata(matrix_ref)
    fields = ("id", "parents", "size", "version", "md5Checksum", "trashed")
    if any(before.get(k) != after.get(k) for k in fields):
        raise WorkflowError("matrix changed during observation")
    if before.get("md5Checksum") != hashlib.md5(matrix).hexdigest():
        raise WorkflowError("matrix content does not match metadata")
    result = prepare_evidence(tree, matrix)
    result["matrix_ref"] = matrix_ref
    result["matrix_version"] = after.get("version")
    result["matrix_name"] = selected[0][1]["name"]
    return result


def validate_snapshot_directory(directory):
    """Require a private agent-owned directory with safe ancestors."""
    directory = Path(directory)
    if not directory.is_absolute() or ".." in directory.parts:
        raise WorkflowError("absolute snapshot directory required")
    for parent in (directory, *directory.parents):
        if parent.is_symlink():
            raise WorkflowError("linked snapshot directories are not allowed")
        info = parent.stat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in (0, os.getuid())
            or info.st_mode & 0o022
        ):
            raise WorkflowError("unsafe snapshot directory")
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise WorkflowError("snapshot directory must be private and agent-owned")
    return directory


def publish_evidence(directory, evidence):
    """Atomically replace only this tool's snapshot in an agent-owned directory."""
    directory = validate_snapshot_directory(directory)
    if fcntl is None:
        raise WorkflowError("snapshot publication requires POSIX file locks")
    raw = json.dumps(evidence, ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise WorkflowError("review evidence exceeds output limit")
    destination = directory / "review-evidence.json"
    if destination.is_symlink():
        raise WorkflowError("linked snapshot is not allowed")
    lock_fd = os.open(
        directory / ".evidence.lock",
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    lock_info = os.fstat(lock_fd)
    if (
        not stat.S_ISREG(lock_info.st_mode)
        or lock_info.st_uid != os.getuid()
        or lock_info.st_mode & 0o077
        or lock_info.st_nlink != 1
    ):
        os.close(lock_fd)
        raise WorkflowError("unsafe snapshot lock")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    name = None
    try:
        if destination.is_symlink():
            raise WorkflowError("linked snapshot is not allowed")
        if destination.exists():
            previous = json.loads(destination.read_bytes())
            if previous.get("created_at", 0) > evidence.get("created_at", 0):
                raise WorkflowError("newer evidence already exists")
        fd, name = tempfile.mkstemp(prefix=".evidence-", dir=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, destination)
        fd_dir = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd_dir)
        finally:
            os.close(fd_dir)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)
        os.close(lock_fd)
    return destination


def main():
    parser = argparse.ArgumentParser(
        description="Create read-only document review evidence"
    )
    parser.add_argument("--drive-token-file", required=True)
    parser.add_argument("--root-ref", required=True)
    parser.add_argument("--matrix-ref", required=True)
    parser.add_argument("--matrix-prefix", required=True)
    parser.add_argument("--output-directory", required=True)
    args = parser.parse_args()
    try:
        inventory = DriveInboxInventory(args.drive_token_file)
        reader = DriveArchiveReader(args.drive_token_file, max_bytes=2 * 1024 * 1024)
        evidence = collect_evidence(
            inventory,
            reader,
            root_ref=args.root_ref,
            matrix_ref=args.matrix_ref,
            matrix_prefix=args.matrix_prefix,
        )
        publish_evidence(args.output_directory, evidence)
    except (OSError, ValueError, TypeError, WorkflowError):
        raise SystemExit("Review evidence could not be collected") from None
    print("Review evidence ready; a complete audit has not yet been performed")


if __name__ == "__main__":
    main()
