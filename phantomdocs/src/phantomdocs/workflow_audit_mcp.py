"""Expose one fresh, agent-owned review snapshot through a stdio MCP tool.

The server cannot invoke Drive or modify data. Its host must populate the
snapshot using the agent's credentials and the bounded inventory reader.
"""

import argparse
import hashlib
import json
import os
import select
import stat
import sys
import time
from contextlib import nullcontext
from pathlib import Path

from .workflow_audit_authority import guarded_authorizer
from .workflow_audit_collection import collection_guard
from .workflow_audit_evidence import MAX_EVIDENCE_BYTES

MAX_REQUEST_BYTES = 65536
MAX_AGE_SECONDS = 3600
DELIVERY_TIMEOUT_SECONDS = 5


class DeliveryFailed(Exception):
    """The response could not be delivered within the bounded policy lock."""


def deliver(stdout, text):
    """Bound writes to a real pipe so a stalled client cannot block revocation."""
    if os.name != "posix":
        stdout.write(text)
        stdout.flush()
        return
    try:
        fd = stdout.fileno()
    except (AttributeError, OSError, ValueError):
        stdout.write(text)
        stdout.flush()
        return
    raw = text.encode("utf-8")
    deadline = time.monotonic() + DELIVERY_TIMEOUT_SECONDS
    try:
        stdout.flush()
        old_blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        try:
            offset = 0
            while offset < len(raw):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                    raise DeliveryFailed()
                try:
                    count = os.write(fd, raw[offset : offset + 65536])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise DeliveryFailed()
                offset += count
        finally:
            os.set_blocking(fd, old_blocking)
    except OSError as exc:
        raise DeliveryFailed() from exc


def read_evidence(path, *, now=None, owner_uid=None):
    path = Path(path)
    owner_uid = os.getuid() if owner_uid is None else owner_uid
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute evidence file required")
    if type(owner_uid) is not int or owner_uid < 0 or os.name != "posix":
        raise ValueError("POSIX evidence owner required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        for component in path.parts[1:-1]:
            info = os.fstat(directory)
            if info.st_uid not in (0, owner_uid) or info.st_mode & 0o022:
                raise ValueError("unsafe evidence directory")
            child = os.open(component, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid not in (0, owner_uid) or info.st_mode & 0o022:
            raise ValueError("unsafe evidence directory")
        with collection_guard(directory, owner_uid, writer=False):
            fd = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
            )
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != owner_uid
                    or info.st_nlink != 1
                    or info.st_mode & 0o077
                ):
                    raise ValueError("unsafe evidence file")
                raw = stream.read(MAX_EVIDENCE_BYTES + 1)
    finally:
        os.close(directory)
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence too large")
    data = json.loads(raw)
    created = data.get("created_at") if isinstance(data, dict) else None
    current = time.time() if now is None else now
    if (
        not isinstance(data, dict)
        or data.get("kind") != "document-review-evidence"
        or data.get("version") != 1
        or data.get("complete_audit") is not False
        or type(created) is not int
        or not 0 <= current - created <= MAX_AGE_SECONDS
        or not isinstance(data.get("matrix_text"), str)
        or data.get("matrix_sha256")
        != hashlib.sha256(data.get("matrix_text", "").encode("utf-8")).hexdigest()
    ):
        raise ValueError("evidence is invalid or expired")
    return data


def dispatch(request, path, authorize=None, evidence_provider=None):
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        raise ValueError("invalid request")
    method, params = request.get("method"), request.get("params", {})
    if method == "initialize":
        version = params.get("protocolVersion")
        if version not in ("2024-11-05", "2025-03-26", "2025-06-18"):
            version = "2024-11-05"
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "phantomdocs-review", "version": "1"},
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "read_review_evidence",
                    "description": "Read the latest bounded matrix and inventory observations; these are not an audit verdict.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                }
            ]
        }
    if method == "tools/call":
        if (
            params.get("name") != "read_review_evidence"
            or params.get("arguments", {}) != {}
        ):
            raise ValueError("unsupported tool or arguments")
        if authorize is None:
            raise ValueError("current PhantomOrg authorization is required")
        evidence = evidence_provider() if evidence_provider else read_evidence(path)
        authorize(evidence)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(evidence, ensure_ascii=False),
                }
            ]
        }
    raise ValueError("unsupported method")


def serve(path, stdin, stdout, config_path=None, evidence_provider=None):
    while True:
        raw = stdin.readline(MAX_REQUEST_BYTES + 1)
        if not raw:
            break
        identity = None
        try:
            if len(raw.encode("utf-8")) > MAX_REQUEST_BYTES or not raw.endswith("\n"):
                break
            request = json.loads(raw)
            identity = request.get("id") if isinstance(request, dict) else None
            if identity is None:
                continue
            guard = (
                guarded_authorizer(config_path)
                if config_path and request.get("method") == "tools/call"
                else nullcontext((lambda evidence: None) if evidence_provider else None)
            )
            with guard as authorize:
                result = dispatch(request, path, authorize, evidence_provider)
                response = {"jsonrpc": "2.0", "id": identity, "result": result}
                encoded = json.dumps(response, ensure_ascii=False) + "\n"
                if len(encoded.encode("utf-8")) > 8 * 1024 * 1024:
                    raise ValueError("response too large")
                deliver(stdout, encoded)
                continue
        except DeliveryFailed:
            return
        except (OSError, ValueError, TypeError, KeyError):
            response = {
                "jsonrpc": "2.0",
                "id": identity,
                "error": {"code": -32603, "message": "Review evidence unavailable"},
            }
        stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        stdout.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence")
    parser.add_argument("--authorization-config")
    parser.add_argument("--peer-socket")
    args = parser.parse_args()
    if args.peer_socket:
        if args.evidence or args.authorization_config:
            parser.error("peer and direct authorization modes cannot be combined")
        from .workflow_audit_peer import request_evidence

        serve(
            None,
            sys.stdin,
            sys.stdout,
            evidence_provider=lambda: request_evidence(
                args.peer_socket, expected_server_uid=0
            ),
        )
    else:
        if not args.evidence or not args.authorization_config:
            parser.error(
                "direct mode requires evidence and authorization configuration"
            )
        serve(args.evidence, sys.stdin, sys.stdout, args.authorization_config)


if __name__ == "__main__":
    main()
