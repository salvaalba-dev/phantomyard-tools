"""Linux-only integration experiment using synthetic policy and requests."""

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import yaml
from test_guarded_service import org_fixture

from phantomdocs.access import can_write, load_org
from phantomdocs.workflow_local_peer_service import serve_one
from phantomdocs.workflow_policy_sync import synchronize


@unittest.skipUnless(
    sys.platform == "linux" and os.geteuid() == 0, "requires root on Linux"
)
class PolicyServiceCoordinationTests(unittest.TestCase):
    def test_policy_sync_waits_for_live_request_and_next_request_sees_revocation(self):
        with tempfile.TemporaryDirectory(
            prefix="policy-service-test-", dir="/root"
        ) as folder:
            root = Path(folder)
            source, destination, lock_path = (
                root / name for name in ("source", "org", "lock")
            )
            policy = org_fixture()
            destination.write_text(yaml.safe_dump(policy))
            policy["actors"][0]["actor_exceptions"] = []
            source.write_text(yaml.safe_dump(policy))
            lock_path.touch(mode=0o600)
            started, release, updated = (threading.Event() for _ in range(3))
            errors = []

            class Ledger:
                def accept_local(self, job, org, actor, make_plan):
                    if not started.is_set():
                        started.set()
                        if not release.wait(5):
                            raise TimeoutError("synthetic request timed out")
                    allowed = can_write(org, actor, job["category"], ["lead"])
                    return {"state": "accepted" if allowed else "blocked"}

            @contextmanager
            def context(org):
                yield {
                    "org": org,
                    "identity_map": "/synthetic/map",
                    "ledger": Ledger(),
                    "make_plan": None,
                }

            def synchronize_policy():
                try:
                    synchronize(str(source), str(destination), str(lock_path))
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                finally:
                    updated.set()

            def request(number, coordinate=False):
                path = str(root / f"peer-{number}.sock")
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(path)
                listener.listen(1)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(5)

                def serve():
                    try:
                        serve_one(
                            listener,
                            context,
                            policy_lock=str(lock_path),
                            load_org=lambda: load_org(str(destination)),
                        )
                    except Exception as exc:  # noqa: BLE001
                        errors.append(exc)

                worker = threading.Thread(target=serve)
                worker.start()
                try:
                    client.connect(path)
                    client.sendall(b'{"job":{"category":"category-4-project-a"}}\n')
                    if coordinate:
                        self.assertTrue(started.wait(3))
                        writer = threading.Thread(target=synchronize_policy)
                        writer.start()
                        try:
                            self.assertFalse(updated.wait(0.2))
                        finally:
                            release.set()
                        response = json.loads(client.recv(1024))
                        writer.join(5)
                        self.assertFalse(writer.is_alive())
                        self.assertTrue(updated.is_set())
                    else:
                        response = json.loads(client.recv(1024))
                    worker.join(5)
                    self.assertFalse(worker.is_alive())
                    return response
                finally:
                    release.set()
                    client.close()
                    listener.close()
                    if os.path.exists(path):
                        os.unlink(path)

            with patch(
                "phantomdocs.workflow_local_peer.resolve_peer_actor",
                return_value="project_actor",
            ):
                self.assertEqual(request(1, coordinate=True), {"status": "received"})
                self.assertEqual(request(2), {"status": "blocked"})
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
