"""Experimental CLI bridge for local workflow admission.

This accepts a complete workflow job, not arbitrary ``pd add`` arguments.
It never claims that admission processes, archives or registers the document.
"""

import json
import os
from pathlib import Path

import click

from phantomdocs.workflow_admission_client import PeerClientError, request_peer
from phantomdocs.workflow_admission_config import load_config
from phantomdocs.workflows import validate_job

MAX_JOB_BYTES = 60 * 1024


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate job field")
        result[key] = value
    return result


def read_job(path):
    try:
        with Path(path).open("rb") as source:
            raw = source.read(MAX_JOB_BYTES + 1)
        if not raw or len(raw) > MAX_JOB_BYTES:
            raise ValueError("job size")
        job = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        validate_job(job)
        return job
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("invalid or inaccessible workflow job") from exc


@click.command("submit-workflow")
@click.option("--job", required=True, type=click.Path(dir_okay=False))
@click.option("--actor", required=True)
@click.option("--org-yaml", required=True)
@click.option("--root", required=True)
@click.option(
    "--service-config", default="/etc/phantomdocs/admission.json", show_default=True
)
def submit_workflow(job, actor, org_yaml, root, service_config):
    """Submit a job to a locally authenticated workflow admission service."""
    try:
        config = load_config(service_config)
        document = read_job(job)
        if (
            document["requester"] != actor
            or not os.path.isabs(root)
            or not os.path.isabs(org_yaml)
            or os.path.normpath(root) != config["store_path"]
            or os.path.normpath(org_yaml) != config["org_path"]
        ):
            raise ValueError("job or target does not match configured context")
        response = request_peer(
            config["socket_path"], config["server_uid"], {"job": document}
        )
    except (OSError, ValueError, PeerClientError) as exc:
        raise click.ClickException(
            "submission unavailable; review the request before retrying"
        ) from exc
    if response["status"] == "rejected":
        raise click.ClickException("request rejected")
    if response["status"] == "blocked":
        click.echo("Request received but blocked; document has not been registered.")
        raise click.exceptions.Exit(2)
    click.echo("Request received for review; document has not been registered.")
