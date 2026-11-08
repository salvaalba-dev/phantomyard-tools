"""Per-connection local viewer worker; no listener is created here.

The host must provide an accepted Unix socket and fixed account bindings from
protected configuration. Reader-side authorization and revalidation remain
mandatory. No claims in a request frame select the agent or peer account.
"""

import argparse
import asyncio
import contextlib
import json
import os
import socket
import struct
import threading

from phantomdocs.view_agent_conversation import ask_persona

MAX_FRAME = 16384


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate request field")
        result[key] = value
    return result


async def serve_connection(connection, *, reader_uid, agent_uid, persona, executable):
    """Serve one locally authenticated reader over a bounded Unix socket."""
    if (
        connection.family != getattr(socket, "AF_UNIX", None)
        or not hasattr(socket, "SO_PEERCRED")
        or type(reader_uid) is not int
        or reader_uid <= 0
        or reader_uid == agent_uid
    ):
        connection.close()
        return False
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, _gid = struct.unpack("3i", raw)
        if pid <= 0 or uid != reader_uid:
            connection.close()
            return False
        connection.setblocking(False)
        reader, writer = await asyncio.open_unix_connection(sock=connection)
    except (OSError, ValueError, struct.error):
        connection.close()
        return False
    cancelled = threading.Event()
    task = watch = None
    try:
        size = struct.unpack(
            "!I", await asyncio.wait_for(reader.readexactly(4), timeout=3)
        )[0]
        if not 0 < size <= MAX_FRAME:
            raise ValueError("Invalid request size")
        raw = await asyncio.wait_for(reader.readexactly(size), timeout=3)
        payload = json.loads(raw, object_pairs_hook=_unique)
        task = asyncio.create_task(
            ask_persona(
                payload,
                persona=persona,
                executable=executable,
                expected_uid=agent_uid,
                cancelled=cancelled,
            )
        )
        watch = asyncio.create_task(reader.read(1))
        done, _pending = await asyncio.wait(
            {task, watch}, return_when=asyncio.FIRST_COMPLETED
        )
        if watch in done:
            cancelled.set()
            with contextlib.suppress(Exception):
                await task
            return False
        result = await task
        data = json.dumps(
            result, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode()
        if len(data) > 64000:
            raise ValueError("Response exceeds bounds")
        writer.write(struct.pack("!I", len(data)) + data)
        await asyncio.wait_for(writer.drain(), timeout=3)
        return True
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        asyncio.IncompleteReadError,
        asyncio.TimeoutError,
        json.JSONDecodeError,
    ):
        return False
    finally:
        cancelled.set()
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if watch is not None:
            watch.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await watch
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


def main():
    """Use one connected descriptor passed by systemd socket activation."""
    parser = argparse.ArgumentParser(
        description="Handle one fixed viewer agent connection"
    )
    parser.add_argument("--reader-uid", type=int, required=True)
    parser.add_argument("--agent-uid", type=int, required=True)
    parser.add_argument("--persona", required=True)
    parser.add_argument("--executable", required=True)
    args = parser.parse_args()
    if (
        os.name != "posix"
        or os.getuid() != args.agent_uid
        or args.agent_uid <= 0
        or os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
    ):
        raise SystemExit(
            "A single systemd connection and fixed agent account are required"
        )
    try:
        connection = socket.socket(fileno=3)
        if (
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            != socket.SOCK_STREAM
        ):
            connection.close()
            raise ValueError("A connected stream is required")
        success = asyncio.run(
            serve_connection(
                connection,
                reader_uid=args.reader_uid,
                agent_uid=args.agent_uid,
                persona=args.persona,
                executable=args.executable,
            )
        )
    except (OSError, ValueError):
        raise SystemExit("Viewer agent connection unavailable") from None
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
