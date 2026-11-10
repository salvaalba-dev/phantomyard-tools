import socket
import struct
from contextlib import contextmanager

from phantomdocs import view_matrix_broker as broker


def test_broker_holds_authority_until_delivery_ack(monkeypatch):
    state = {"locked": False, "closed": False, "sent": []}
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)

    class Connection:
        family = socket.AF_UNIX
        type = socket.SOCK_STREAM
        incoming = bytearray(b'{"version":"v2"}\ndelivered\n')

        def settimeout(self, timeout):
            assert timeout > 0

        def getsockopt(self, *args):
            return struct.pack("3i", 99, 123, 123)

        def recv(self, length):
            if self.incoming.startswith(b"delivered"):
                assert state["locked"]
            result = bytes(self.incoming[:length])
            del self.incoming[:length]
            return result

        def sendall(self, data):
            assert state["locked"]
            state["sent"].append(data)

        def close(self):
            state["closed"] = True

    @contextmanager
    def authority(actor):
        assert actor == "agent"
        state["locked"] = True
        try:
            yield {}, {}, object()
        finally:
            state["locked"] = False

    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(broker, "read_matrix", lambda **kwargs: "verified")
    broker.serve(
        Connection(), client_uid=123, actor="agent", binding={}, authority=authority
    )
    assert state == {
        "locked": False,
        "closed": True,
        "sent": [b'{"matrix": "verified"}\n'],
    }
