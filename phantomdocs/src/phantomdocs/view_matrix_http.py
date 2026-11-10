"""Opt-in matrix endpoint for the existing identified PhantomView handler."""

import os
import re

from .view_matrix_client import deliver
from .workflow_admission_config import _json
from .workflows import WorkflowError

_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


def dispatch(handler, backend, path):
    """Serve one scoped matrix; no request-controlled actor or Drive ref."""
    prefix = "/api/matrix/"
    if not path.startswith(prefix):
        return False
    version = path.removeprefix(prefix)
    config_path = os.environ.get("PHANTOMVIEW_MATRIX_ROUTES")
    started = False

    def send(text):
        nonlocal started
        previous = handler.connection.gettimeout()
        handler.connection.settimeout(5)
        try:
            started = True
            handler.send(200, {"version": version, "content": text})
        finally:
            handler.connection.settimeout(previous)

    try:
        if not _VERSION.fullmatch(version) or not config_path:
            raise ValueError("matrix unavailable")
        config = _json(config_path)
        if (
            not isinstance(config, dict)
            or set(config) != {"version", "routes"}
            or config["version"] != 1
        ):
            raise ValueError("matrix unavailable")
        deliver(
            gate=backend.gate,
            headers=handler.headers,
            version=version,
            routes=config["routes"],
            send=send,
        )
    except (OSError, ValueError, TypeError, KeyError, WorkflowError):
        if not started:
            handler.send(404, {"error": "Matrix unavailable"})
    return True
