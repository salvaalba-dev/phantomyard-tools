"""Linux-only synthetic end-to-end admission with a real unprivileged peer."""

import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest
import test_workflow_scan as fixtures
import yaml

from phantomdocs import workflow_admission_client as peer_client
from phantomdocs import workflow_admission_host as admission_host
from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_scan import scan


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root for a synthetic unprivileged peer",
)
@pytest.mark.parametrize(
    ("requester_mode", "mapped_actor", "expected"),
    [
        (False, "coordinator", "received"),
        (True, "coordinator", "received"),
        (True, "remote-lead", "rejected"),
    ],
)
def test_real_unprivileged_peer_is_bound_to_phantomorg_actor(
    requester_mode, mapped_actor, expected
):
    system = fixtures.system.__wrapped__()
    if requester_mode:
        system[1]["processor"]["source"] = "authenticated-requester"
    processor = None if requester_mode else system[4]
    job = scan(*system[:4], processor, *system[5:])["items"][0]["job"]
    with tempfile.TemporaryDirectory(prefix="pd-admission-test-", dir="/run") as root:
        directory = Path(root)
        directory.chmod(0o711)
        socket_path = str(directory / "peer.sock")
        lock_path = directory / "policy.lock"
        lock_path.write_text("", encoding="utf-8")
        lock_path.chmod(0o644)
        identity_path = directory / "identities.json"
        identity_path.write_text(
            json.dumps({"version": 1, "actors": {"65534": mapped_actor}}),
            encoding="utf-8",
        )
        identity_path.chmod(0o600)
        private = directory / "ledger"
        private.mkdir(mode=0o700)
        ledger_path = private / "jobs.sqlite"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(socket_path)
        os.chmod(socket_path, 0o666)  # Synthetic socket, protected by peer identity.
        listener.listen(1)
        listener.settimeout(10)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                listener.close()
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                response = peer_client.request_peer(socket_path, 0, {"job": job})
                os.write(write_fd, json.dumps(response).encode())
                os._exit(0)
            except BaseException:  # noqa: BLE001 - never return into pytest in the child
                os._exit(1)
        os.close(write_fd)
        try:
            admission_host.serve_admission_once(
                listener,
                identity_map=str(identity_path),
                ledger_path=ledger_path,
                policy_lock=str(lock_path),
                load_org=lambda: system[2],
                load_installation=lambda: system[1],
                processor=processor,
            )
            response = os.read(read_fd, 4096)
            _, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) == 0
            assert json.loads(response) == {"status": expected}
            with WorkflowLedger(ledger_path, readonly=True) as ledger:
                assert ledger.connection.execute(
                    "SELECT COUNT(*) FROM jobs"
                ).fetchone()[0] == int(expected == "received")
        finally:
            os.close(read_fd)
            listener.close()


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root for a synthetic unprivileged peer",
)
@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"search": {"query": ""}}, "search"),
        ({"lookup": {"operation": "reference", "ref": "source"}}, "rejected"),
        ({"lookup": {"operation": "reference", "ref": "project-reports"}}, "reference"),
    ],
)
def test_real_peer_queries_filter_by_phantomorg_category(payload, expected):
    system = fixtures.system.__wrapped__()
    fixtures.index(system, category="category-3")
    with tempfile.TemporaryDirectory(prefix="pd-search-test-", dir="/run") as root:
        directory = Path(root)
        directory.chmod(0o711)
        socket_path = str(directory / "peer.sock")
        lock_path = directory / "policy.lock"
        lock_path.write_text("", encoding="utf-8")
        lock_path.chmod(0o644)
        identity_path = directory / "identities.json"
        identity_path.write_text(
            json.dumps({"version": 1, "actors": {"65534": "coordinator"}}),
            encoding="utf-8",
        )
        identity_path.chmod(0o600)
        private = directory / "private"
        private.mkdir(mode=0o700)
        (private / "manifest.yaml").write_text(
            yaml.safe_dump(system[6]), encoding="utf-8"
        )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(socket_path)
        os.chmod(socket_path, 0o666)  # Synthetic socket, protected by peer identity.
        listener.listen(1)
        listener.settimeout(10)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                listener.close()
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                response = peer_client.request_peer(socket_path, 0, payload)
                os.write(write_fd, json.dumps(response).encode())
                os._exit(0)
            except BaseException:  # noqa: BLE001 - never return into pytest in the child
                os._exit(1)
        os.close(write_fd)
        try:
            admission_host.serve_admission_once(
                listener,
                identity_map=str(identity_path),
                ledger_path=private / "jobs.sqlite",
                policy_lock=str(lock_path),
                load_org=lambda: system[2],
                load_installation=lambda: system[1],
                processor=system[4],
                search_store_path=private,
            )
            response = os.read(read_fd, 4096)
            _, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) == 0
            result = json.loads(response)
            if expected == "rejected":
                assert result == {"status": "rejected"}
            elif expected == "search":
                assert result["actor"] == "coordinator"
                assert result["items"] == [
                    {"kind": "folder", "urn": "urn:example-org:folder:project-reports"}
                ]
            else:
                assert result == {
                    "status": "ok",
                    "actor": "coordinator",
                    "result": {
                        "urn": "urn:example-org:folder:project-reports",
                        "location": "",
                    },
                }
        finally:
            os.close(read_fd)
            listener.close()
