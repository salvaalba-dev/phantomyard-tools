"""Search a protected local store through an authenticated peer service."""

import os

import click

from .storage import StorageError, read_location
from .workflow_admission_client import PeerClientError, request_peer
from .workflow_admission_config import load_config

DEFAULT_CONFIG = "/etc/phantomdocs/admission.json"


def search_configured(query, *, actor, org_yaml, root, config_path=DEFAULT_CONFIG):
    """Return only results from the configured service for this local actor."""
    result = _request_configured(
        {"search": {"query": query}},
        actor=actor,
        org_yaml=org_yaml,
        root=root,
        config_path=config_path,
    )
    for item in result["items"]:
        if not item["urn"].isprintable():
            raise click.ClickException("protected search unavailable or denied")
    return result["items"]


def lookup_configured(operation, ref, *, actor, org_yaml, root, mac=None):
    """Resolve an authorized reference or version history through the peer."""
    payload = {"operation": operation, "ref": ref}
    if mac is not None:
        payload["mac"] = mac
    result = _request_configured(
        {"lookup": payload}, actor=actor, org_yaml=org_yaml, root=root
    )["result"]
    if operation in {"reference", "content-reference"} and any(
        value and not value.isprintable() for value in result.values()
    ):
        raise click.ClickException("protected lookup unavailable or denied")
    return result


def read_scoped_drive_content(ref, *, actor, org_yaml, root, mac=None):
    """Verify caller-owned Drive bytes and recheck access before returning them."""
    details = lookup_configured(
        "content-reference", ref, actor=actor, org_yaml=org_yaml, root=root, mac=mac
    )
    file_id = details["location"].removeprefix("gdrive://")
    try:
        content = read_location(
            {"backend": "gdrive", "ref": file_id},
            details["contentHash"],
            root=root,
            streaming=True,
        )
    except (OSError, ValueError, StorageError) as exc:
        raise click.ClickException("protected content unavailable or changed") from exc
    try:
        current = lookup_configured(
            "content-reference", ref, actor=actor, org_yaml=org_yaml, root=root, mac=mac
        )
        if current != details:
            raise click.ClickException("protected content unavailable or changed")
        return details, content
    except BaseException:
        content.close()
        raise


def _request_configured(request, *, actor, org_yaml, root, config_path=DEFAULT_CONFIG):
    try:
        config = load_config(config_path)
        if (
            not actor
            or not org_yaml
            or not os.path.isabs(root)
            or not os.path.isabs(org_yaml)
            or os.path.normpath(root) != config["store_path"]
            or os.path.normpath(org_yaml) != config["org_path"]
        ):
            raise ValueError("search target does not match protected configuration")
        result = request_peer(config["socket_path"], config["server_uid"], request)
        if result.get("status") != "ok" or result.get("actor") != actor:
            raise ValueError("search actor was not authenticated")
        return result
    except (OSError, ValueError, KeyError, TypeError, PeerClientError) as exc:
        raise click.ClickException("protected search unavailable or denied") from exc
