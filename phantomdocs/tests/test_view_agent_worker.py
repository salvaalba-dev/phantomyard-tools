import asyncio
import json
import os
import socket
import struct
from types import SimpleNamespace

import pytest

from phantomdocs import view_agent_worker as worker
from phantomdocs.view_agent_worker import _unique, serve_connection


def test_duplicate_frame_fields_are_rejected():
    with pytest.raises(ValueError):
        _unique([("scope", "one"), ("scope", "two")])


def test_network_peer_is_closed_without_reading():
    closed = []
    fake = SimpleNamespace(family=0, close=lambda: closed.append(True))
    assert not asyncio.run(
        serve_connection(
            fake, reader_uid=1, agent_uid=2, persona="agent", executable="/bin/false"
        )
    )
    assert closed == [True]


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SO_PEERCRED"),
    reason="Linux peer credentials required",
)
def test_authenticated_local_peer_round_trip(monkeypatch):
    if os.getuid() == 0:
        pytest.skip("A non-root synthetic reader account is required")

    async def synthetic_ask(payload, **_options):
        return {
            "schema_version": 1,
            "request_id": payload["request_id"],
            "persona": "agent",
            "status": "complete",
            "text": "synthetic",
        }

    monkeypatch.setattr(worker, "ask_persona", synthetic_ask)

    async def run():
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        client.setblocking(False)
        uid = os.getuid()
        task = asyncio.create_task(
            serve_connection(
                server,
                reader_uid=uid,
                agent_uid=uid + 1,
                persona="agent",
                executable="/bin/false",
            )
        )
        reader, writer = await asyncio.open_unix_connection(sock=client)
        raw = json.dumps({"request_id": "synthetic"}).encode()
        writer.write(struct.pack("!I", len(raw)) + raw)
        await writer.drain()
        size = struct.unpack("!I", await reader.readexactly(4))[0]
        assert json.loads(await reader.readexactly(size))["text"] == "synthetic"
        assert await task
        writer.close()
        await writer.wait_closed()

    asyncio.run(run())
