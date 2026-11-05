"""Tests of the experimental peer service using synthetic requests only."""

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

from phantomdocs.access import can_write
from phantomdocs.workflow_local_peer_service import serve_one


def org_fixture():
    return {
        "version": 1,
        "policies": {
            "access_levels": {"base": {"categories": []}},
            "security_categories": {
                "category-4": {},
                "category-4-project-a": {"parent": "category-4"},
                "category-4-project-b": {"parent": "category-4"},
            },
        },
        "roles": [{"id": "lead", "access_level": "base", "security_exceptions": []}],
        "actors": [
            {
                "id": "project_actor",
                "role": "lead",
                "actor_exceptions": ["category-4-project-a"],
            }
        ],
    }


class GuardedPeerServiceTests(unittest.TestCase):
    def test_service_rejects_unsupported_policy_before_opening_context(self):
        events = []

        class Connection:
            def close(self):
                events.append("peer-close")

        class Listener:
            family = 12345
            type = socket.SOCK_STREAM

            def getsockopt(self, *args):
                return 1

            def accept(self):
                return Connection(), None

        @contextmanager
        def lock(path, *, exclusive):
            events.append("lock")
            try:
                yield
            finally:
                events.append("unlock")

        def context(_org):
            self.fail("unsupported policy reached the service context")

        with (  # noqa: SIM117
            patch("phantomdocs.workflow_local_peer_service.socket.socket", Listener),
            patch(
                "phantomdocs.workflow_local_peer_service.socket.AF_UNIX",
                12345,
                create=True,
            ),
            patch("phantomdocs.workflow_local_peer_service.policy_guard", lock),
        ):
            with self.assertRaisesRegex(ValueError, "schema version"):
                serve_one(
                    Listener(),
                    context,
                    policy_lock="/protected/policy.lock",
                    load_org=lambda: {"version": 99},
                )
        self.assertEqual(events, ["lock", "unlock", "peer-close"])

    @unittest.skipUnless(sys.platform == "linux", "requires Linux Unix sockets")
    def test_request_uses_guarded_fresh_policy_and_closes_context(self):
        events = []
        org = org_fixture()

        class Ledger:
            def accept_local(self, job, loaded, actor, make_plan):
                events.append("admit")
                permitted = can_write(loaded, actor, job["category"], ["lead"])
                return {"state": "accepted" if permitted else "blocked"}

        @contextmanager
        def lock(path, *, exclusive):
            self.assertEqual((path, exclusive), ("/protected/policy.lock", False))
            events.append("lock")
            try:
                yield
            finally:
                events.append("unlock")

        def load_org():
            events.append("load")
            return org

        @contextmanager
        def context(snapshot):
            events.append("open")
            try:
                yield {
                    "org": snapshot,
                    "identity_map": "/trusted/map",
                    "ledger": Ledger(),
                    "make_plan": None,
                }
            finally:
                events.append("close")

        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "peer.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)
            errors = []

            def serve():
                try:
                    serve_one(
                        listener,
                        context,
                        policy_lock="/protected/policy.lock",
                        load_org=load_org,
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(3)
            try:
                with (
                    patch("phantomdocs.workflow_local_peer_service.policy_guard", lock),
                    patch(
                        "phantomdocs.workflow_local_peer.resolve_peer_actor",
                        return_value="project_actor",
                    ),
                ):
                    worker = threading.Thread(target=serve)
                    worker.start()
                    client.connect(path)
                    client.sendall(b'{"job":{"category":"category-4-project-a"}}\n')
                    self.assertEqual(
                        json.loads(client.recv(1024)), {"status": "received"}
                    )
                    worker.join(3)
                    self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(
                    events, ["lock", "load", "open", "admit", "close", "unlock"]
                )
                self.assertEqual(client.recv(1), b"")
            finally:
                client.close()
                listener.close()
                if os.path.exists(path):
                    os.unlink(path)

    def test_service_rejects_changed_policy_before_admission(self):
        events = []

        class Connection:
            def close(self):
                events.append("peer-close")

        class Listener:
            family = 12345
            type = socket.SOCK_STREAM

            def getsockopt(self, *args):
                return 1

            def accept(self):
                return Connection(), None

        @contextmanager
        def lock(path, *, exclusive):
            events.append("lock")
            try:
                yield
            finally:
                events.append("unlock")

        @contextmanager
        def context(org):
            changed = org_fixture()
            changed["actors"][0]["actor_exceptions"] = []
            try:
                yield {"org": changed}
            finally:
                events.append("close")

        with (
            patch("phantomdocs.workflow_local_peer_service.socket.socket", Listener),
            patch(
                "phantomdocs.workflow_local_peer_service.socket.AF_UNIX",
                12345,
                create=True,
            ),
            patch("phantomdocs.workflow_local_peer_service.policy_guard", lock),
            patch("phantomdocs.workflow_local_peer_service.serve_connection") as admit,
        ):
            with self.assertRaisesRegex(ValueError, "different policy"):
                serve_one(
                    Listener(),
                    context,
                    policy_lock="/protected/policy.lock",
                    load_org=org_fixture,
                )
            admit.assert_not_called()
        self.assertEqual(events, ["lock", "close", "unlock", "peer-close"])


if __name__ == "__main__":
    unittest.main()
