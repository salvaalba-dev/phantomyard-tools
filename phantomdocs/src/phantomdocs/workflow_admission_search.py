"""Search a protected local store through an authenticated peer service."""

import os

import click

from .workflow_admission_client import PeerClientError, request_peer
from .workflow_admission_config import load_config

DEFAULT_CONFIG = "/etc/phantomdocs/admission.json"


def search_configured(query, *, actor, org_yaml, root, config_path=DEFAULT_CONFIG):
    """Return only results from the configured service for this local actor."""
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
        result = request_peer(
            config["socket_path"], config["server_uid"], {"search": {"query": query}}
        )
        if result.get("status") != "ok" or result.get("actor") != actor:
            raise ValueError("search actor was not authenticated")
        for item in result["items"]:
            if not item["urn"].isprintable():
                raise ValueError("invalid search result")
        return result["items"]
    except (OSError, ValueError, KeyError, TypeError, PeerClientError) as exc:
        raise click.ClickException("protected search unavailable or denied") from exc
