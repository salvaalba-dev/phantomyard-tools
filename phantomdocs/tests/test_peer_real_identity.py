"""Synthetic Linux proof of kernel peer identity and scoped authorization."""

import json
import os
import socket
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from test_guarded_service import org_fixture

from phantomdocs.access import can_write
from phantomdocs.workflow_local_peer_service import serve_one


@unittest.skipUnless(
    sys.platform == "linux" and os.geteuid() == 0,
    "requires root and Linux peer credentials",
)
class PeerRealIdentityTests(unittest.TestCase):
    def test_kernel_uid_controls_project_scope_and_unmapped_account_is_denied(self):
        with (
            tempfile.TemporaryDirectory(prefix="peer-policy-", dir="/root") as private,
            tempfile.TemporaryDirectory(prefix="peer-socket-", dir="/tmp") as sockets,
        ):
            private = Path(private)
            lock = private / "policy.lock"
            lock.touch(mode=0o600)
            identity_map = private / "actors.json"
            identity_map.write_text(
                json.dumps({"version": 1, "actors": {"65534": "project_actor"}})
            )
            identity_map.chmod(0o600)
            os.chmod(sockets, 0o711)

            class Ledger:
                def accept_local(self, job, org, actor, make_plan):
                    allowed = can_write(org, actor, job["category"], ["lead"])
                    return {"state": "accepted" if allowed else "blocked"}

            @contextmanager
            def context(org):
                yield {
                    "org": org,
                    "identity_map": str(identity_map),
                    "ledger": Ledger(),
                    "make_plan": None,
                }

            def run_request(uid, category, index):
                path = str(Path(sockets) / f"peer-{index}.sock")
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(path)
                os.chmod(path, 0o666)
                listener.listen(1)
                listener.settimeout(5)
                read_fd, write_fd = os.pipe()
                pid = os.fork()
                if pid == 0:
                    try:
                        os.close(read_fd)
                        listener.close()
                        os.setgroups([])
                        os.setgid(uid)
                        os.setuid(uid)
                        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        client.settimeout(5)
                        client.connect(path)
                        client.sendall(
                            json.dumps({"job": {"category": category}}).encode() + b"\n"
                        )
                        os.write(write_fd, client.recv(1024))
                        client.close()
                        os._exit(0)
                    except BaseException:  # noqa: BLE001
                        os._exit(1)
                os.close(write_fd)
                try:
                    serve_one(
                        listener, context, policy_lock=str(lock), load_org=org_fixture
                    )
                    payload = os.read(read_fd, 1024)
                    _, status = os.waitpid(pid, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    return json.loads(payload)
                finally:
                    os.close(read_fd)
                    listener.close()
                    os.unlink(path)
                    try:
                        os.waitpid(pid, 0)
                    except ChildProcessError:
                        pass

            self.assertEqual(
                run_request(65534, "category-4-project-a", 1), {"status": "received"}
            )
            self.assertEqual(
                run_request(65534, "category-4-project-b", 2), {"status": "blocked"}
            )
            self.assertEqual(
                run_request(65533, "category-4-project-a", 3), {"status": "rejected"}
            )


if __name__ == "__main__":
    unittest.main()
