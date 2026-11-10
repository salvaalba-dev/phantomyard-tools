import socket
import struct
from types import SimpleNamespace

import pytest

from phantomdocs import view_matrix_client as client
from phantomdocs.workflows import WorkflowError


def test_client_authenticates_broker_and_rechecks_session(monkeypatch):
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(client, "project_category", lambda *args: "project-category")
    recipient = SimpleNamespace(persona="agent", human=None)
    state = {"changed": False, "calls": 0, "sent": [], "wire": []}

    class Directory:
        def __init__(self):
            self.org = {"organization": {"id": "org"}}

        def permits(self, current, resource):
            return current == recipient and resource["project"] == "project"

    class Gate:
        def identified_scope(self, headers):
            state["calls"] += 1
            return (
                SimpleNamespace(persona="other", human=None)
                if state["changed"]
                else recipient
            ), Directory()

    class Connection:
        def __init__(self):
            self.incoming = bytearray(b'{"matrix":"verified"}\n')

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def connect(self, path):
            assert path == "/run/broker.sock"

        def getsockopt(self, *args):
            return struct.pack("3i", 99, 0, 0)

        def sendall(self, data):
            state["wire"].append(data)

        def recv(self, count):
            result = bytes(self.incoming[:count])
            del self.incoming[:count]
            return result

    monkeypatch.setattr(socket, "socket", lambda *args: Connection())
    routes = {
        "agent": {
            "socket": "/run/broker.sock",
            "server_uid": 0,
            "domain": "dept",
            "project_type": "project",
            "scope_id": "project",
        }
    }
    client.deliver(
        gate=Gate(), headers={}, version="v2", routes=routes, send=state["sent"].append
    )
    assert state["sent"] == ["verified"]
    assert state["wire"][-1] == b"delivered\n"

    class ChangingGate(Gate):
        def identified_scope(self, headers):
            if state["calls"]:
                state["changed"] = True
            return super().identified_scope(headers)

    state["calls"] = 0
    with pytest.raises(WorkflowError):
        client.deliver(
            gate=ChangingGate(),
            headers={},
            version="v2",
            routes=routes,
            send=state["sent"].append,
        )
    assert state["sent"] == ["verified"]
