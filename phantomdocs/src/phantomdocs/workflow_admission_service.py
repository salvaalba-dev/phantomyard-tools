"""Connect protected host configuration to one supervised admission request.

This remains an experimental integration: the caller must supervise the socket,
protect the private ledger, and coordinate every policy writer. No processing,
document writes, Drive operations, or daemon installation are provided here.
"""

import os

from phantomdocs.workflow_admission_config import (
    load_config,
    load_installation,
    load_policy,
    load_processor,
)
from phantomdocs.workflow_admission_host import serve_admission_once


def serve_configured_once(listener, config_path, *, expected_socket=None):
    config = load_config(config_path)
    if not hasattr(os, "geteuid") or os.geteuid() != config["server_uid"]:
        raise ValueError("service account does not match configured server identity")
    if expected_socket is not None and config["socket_path"] != expected_socket:
        raise ValueError("configured socket changed; restart required")
    return serve_admission_once(
        listener,
        identity_map=config["identity_map"],
        ledger_path=config["ledger_path"],
        policy_lock=config["policy_lock"],
        load_org=lambda: load_policy(config["org_path"]),
        load_installation=lambda: load_installation(config["installation_path"]),
        processor=load_processor(
            config["processor_config_path"], config["processor_state_path"]
        ),
    )
