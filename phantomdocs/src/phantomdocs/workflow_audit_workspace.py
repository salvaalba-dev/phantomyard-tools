"""Collect review evidence using an existing agent Workspace integration.

Run as the agent, outside the model sandbox. The caller must provide protected
fixed paths and ensure the process can read the agent's Workspace credentials.
This entry point does not modify Drive or launch an agent turn.
"""

import argparse
import importlib.util
import os
from pathlib import Path

from .workflow_audit_collection import collection_guard
from .workflow_audit_snapshot import (
    collect_evidence,
    publish_evidence,
    validate_snapshot_directory,
)
from .workflow_drive_inventory import DriveInboxInventory
from .workflow_drive_reader import DriveArchiveReader

DRIVE_READONLY = "https://www.googleapis.com/auth/drive.readonly"


def collect_from_workspace(workspace_path, root_ref, matrix_ref, matrix_prefix, output):
    """Use a short-lived read-only token without passing it to the model."""
    if os.name != "posix":
        raise ValueError("Workspace collection requires POSIX file locks")
    output = validate_snapshot_directory(output)
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with collection_guard(directory_fd, os.getuid(), writer=True):
            return _collect(workspace_path, root_ref, matrix_ref, matrix_prefix, output)
    finally:
        os.close(directory_fd)


def _collect(workspace_path, root_ref, matrix_ref, matrix_prefix, output):
    path = Path(workspace_path)
    if not path.is_absolute() or not path.is_file():
        raise ValueError("Workspace tool path must be an existing absolute file")
    spec = importlib.util.spec_from_file_location("agent_workspace", path)
    if spec is None or spec.loader is None:
        raise ValueError("Workspace tool cannot be loaded")
    workspace = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(workspace)
    token = workspace._get_creds([DRIVE_READONLY]).token
    if not isinstance(token, str) or not token:
        raise ValueError("Workspace did not issue a read-only token")
    inventory = DriveInboxInventory.from_token(token)
    reader = DriveArchiveReader.from_token(token, max_bytes=2 * 1024 * 1024)
    evidence = collect_evidence(
        inventory,
        reader,
        root_ref=root_ref,
        matrix_ref=matrix_ref,
        matrix_prefix=matrix_prefix,
    )
    return publish_evidence(output, evidence)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--root-ref", required=True)
    parser.add_argument("--matrix-ref", required=True)
    parser.add_argument("--matrix-prefix", required=True)
    parser.add_argument("--output-directory", required=True)
    args = parser.parse_args()
    try:
        collect_from_workspace(
            args.workspace,
            args.root_ref,
            args.matrix_ref,
            args.matrix_prefix,
            args.output_directory,
        )
    except Exception:  # noqa: BLE001
        raise SystemExit("Review evidence could not be collected") from None
    print("Review evidence ready; a complete audit has not yet been performed")


if __name__ == "__main__":
    main()
