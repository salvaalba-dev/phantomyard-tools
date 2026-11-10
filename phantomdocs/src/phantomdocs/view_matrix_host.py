"""Supervise one fixed-actor broker on a systemd-activated Unix connection."""

import argparse
import os
import socket
import subprocess  # nosec B404 - broker launches a privilege-dropped worker

from .view_matrix_authority import guarded_matrix_authority
from .view_matrix_broker import serve
from .workflow_admission_config import _json


def load_config(path):
    """Load a root-protected binding; the client may choose only a version."""
    value = _json(path)
    fields = {
        "version",
        "actor",
        "client_uid",
        "agent_uid",
        "agent_gid",
        "agent_home",
        "workspace",
        "python",
        "pythonpath",
        "policy_lock",
        "org_path",
        "native_manifest",
        "binding",
    }
    if not isinstance(value, dict) or set(value) != fields or value["version"] != 1:
        raise ValueError("invalid matrix broker configuration")
    for key in ("client_uid", "agent_uid", "agent_gid"):
        if type(value[key]) is not int or value[key] <= 0:
            raise ValueError("invalid matrix broker identity")
    for key in (
        "agent_home",
        "workspace",
        "python",
        "pythonpath",
        "policy_lock",
        "org_path",
        "native_manifest",
    ):
        if not isinstance(value[key], str) or not value[key].startswith("/"):
            raise ValueError("absolute trusted path required")
    if not isinstance(value["actor"], str) or not value["actor"]:
        raise ValueError("invalid matrix actor")
    if not isinstance(value["binding"], dict) or set(value["binding"]) != {
        "versions",
        "root_ref",
        "domain",
        "project_type",
    }:
        raise ValueError("invalid matrix binding")
    return value


def serve_configured(connection, config):
    """Drop privileges for the existing Workspace tool and hold policy locks."""

    def read(ref, limit):
        cmd = [
            config["python"],
            "-m",
            "phantomdocs.view_matrix_worker",
            "--workspace",
            config["workspace"],
            "--uid",
            str(config["agent_uid"]),
            "--ref",
            ref,
            "--limit",
            str(limit),
        ]
        environment = {
            "HOME": config["agent_home"],
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONPATH": config["pythonpath"],
        }
        try:
            result = subprocess.run(  # nosec B603 - protected config, no shell, dropped UID
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
                user=config["agent_uid"],
                group=config["agent_gid"],
                extra_groups=[],
                timeout=25,
                check=True,
            )
        except subprocess.SubprocessError:
            raise ValueError("matrix reader unavailable") from None
        if len(result.stdout) > limit:
            raise ValueError("matrix too large")
        return result.stdout

    def authority(actor):
        if actor != config["actor"]:
            raise ValueError("actor mismatch")
        return guarded_matrix_authority(
            policy_lock=config["policy_lock"],
            org_path=config["org_path"],
            native_manifest=config["native_manifest"],
            reader=read,
        )

    serve(
        connection,
        client_uid=config["client_uid"],
        actor=config["actor"],
        binding=config["binding"],
        authority=authority,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("root-supervised Unix connection required")
    try:
        config = load_config(args.config)
        connection = socket.socket(fileno=os.dup(0))
        serve_configured(connection, config)
    except (OSError, ValueError):
        raise SystemExit("matrix service unavailable") from None


if __name__ == "__main__":
    main()
