"""Bounded read-only traversal for Drive-to-matrix reconciliation."""

import json
from collections import deque

import click

from .workflow_drive_inventory import DriveInboxInventory
from .workflow_scan import _inventory
from .workflows import WorkflowError, reference_is_safe

MAX_FOLDERS = 500
MAX_ITEMS = 5000
MAX_TREE_BYTES = 16 * 1024 * 1024
FOLDER = "application/vnd.google-apps.folder"


def inventory_tree(reader, root_ref, *, max_folders=MAX_FOLDERS, max_items=MAX_ITEMS):
    """Walk direct children without following shortcuts or mutating Drive.

    Each list must be complete, but the overall tree is not a transactional
    snapshot. This output is evidence for reconciliation, not proof that an
    absent file was never registered or authority to alter the matrix.
    """
    if (
        not isinstance(root_ref, str)
        or not root_ref.startswith("gdrive://")
        or not reference_is_safe(root_ref)
        or type(max_folders) is not int
        or not 1 <= max_folders <= MAX_FOLDERS
        or type(max_items) is not int
        or not 1 <= max_items <= MAX_ITEMS
    ):
        raise WorkflowError("invalid tree inventory bounds or root")
    root = root_ref.removeprefix("gdrive://")
    queue = deque([root])
    seen = {root}
    items = []
    folders = 0
    while queue:
        folders += 1
        if folders > max_folders:
            raise WorkflowError("Drive tree exceeds the folder limit")
        folder = queue.popleft()
        page = reader.inventory("gdrive://" + folder)
        _inventory(page)
        for item in page["items"]:
            if folder not in item["parents"]:
                raise WorkflowError("Drive tree item has an unexpected parent")
            if item.get("trashed", False):
                continue
            identity = item.get("id")
            if identity in seen:
                raise WorkflowError("Drive tree has duplicate or cyclic identities")
            seen.add(identity)
            items.append(item)
            if len(items) > max_items:
                raise WorkflowError("Drive tree exceeds the item limit")
            if item.get("mimeType") == FOLDER:
                queue.append(identity)
    result = {"version": 1, "root_ref": root_ref, "complete": True, "items": items}
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_TREE_BYTES:
        raise WorkflowError("Drive tree metadata exceeds the output limit")
    return result


@click.command("tree-inventory")
@click.option("--root-ref", required=True)
@click.option(
    "--drive-token-file", required=True, type=click.Path(exists=True, dir_okay=False)
)
def tree_inventory_command(root_ref, drive_token_file):
    """List bounded Drive tree metadata for review; never change files."""
    try:
        result = inventory_tree(DriveInboxInventory(drive_token_file), root_ref)
    except (WorkflowError, OSError, ValueError, TypeError) as error:
        raise click.ClickException("cannot complete Drive tree inventory") from error
    click.echo(json.dumps(result, indent=2, ensure_ascii=False))
