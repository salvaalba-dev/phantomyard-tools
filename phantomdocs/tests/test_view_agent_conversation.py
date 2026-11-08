import asyncio
import uuid
from types import SimpleNamespace

import pytest

from phantomdocs import view_agent_conversation as adapter


class FakeInput:
    def __init__(self):
        self.data = b""

    def write(self, value):
        self.data += value

    async def drain(self):
        pass

    def close(self):
        pass


class FakeOutput:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    async def read(self, _size):
        return next(self.chunks, b"")


class FakeProcess:
    def __init__(self, chunks):
        self.stdin = FakeInput()
        self.stdout = FakeOutput(chunks)
        self.pid = 90
        self.returncode = None

    async def wait(self):
        self.returncode = 0
        return 0


def test_cli_invocation_preserves_agent_and_bounded_session(monkeypatch):
    process = FakeProcess([b"hello ", b"world", b""])
    calls = []

    async def spawn(*args, **kwargs):
        calls.append((args, kwargs))
        return process

    monkeypatch.setattr(
        adapter, "os", SimpleNamespace(name="posix", getuid=lambda: 123)
    )
    monkeypatch.setattr(
        adapter, "Path", lambda _path: SimpleNamespace(is_absolute=lambda: True)
    )
    monkeypatch.setattr(adapter.asyncio, "create_subprocess_exec", spawn)
    payload = {
        "schema_version": 1,
        "request_id": str(uuid.uuid4()),
        "conversation": "phantomview:" + "a" * 64,
        "question": "hello",
        "evidence": [],
    }
    result = asyncio.run(
        adapter.ask_persona(
            payload,
            persona="agent",
            executable="/opt/bin/phantombot",
            expected_uid=123,
            cancelled=SimpleNamespace(is_set=lambda: False),
        )
    )
    assert result["text"] == "hello world"
    assert result["persona"] == "agent"
    assert calls[0][0] == (
        "/opt/bin/phantombot",
        "ask",
        "-",
        "--persona",
        "agent",
        "--history",
        "--conversation",
        payload["conversation"],
    )
    assert b"hello" in process.stdin.data


def test_refuses_wrong_account_before_launch(monkeypatch):
    monkeypatch.setattr(
        adapter, "os", SimpleNamespace(name="posix", getuid=lambda: 456)
    )
    with pytest.raises(ValueError):
        asyncio.run(
            adapter.ask_persona(
                {},
                persona="agent",
                executable="/opt/bin/phantombot",
                expected_uid=123,
                cancelled=SimpleNamespace(is_set=lambda: False),
            )
        )


def test_oversized_response_terminates_process(monkeypatch):
    process = FakeProcess([b"x" * 4096] * 12)
    killed = []

    async def spawn(*_args, **_kwargs):
        return process

    monkeypatch.setattr(
        adapter,
        "os",
        SimpleNamespace(
            name="posix",
            getuid=lambda: 123,
            killpg=lambda pid, sig: killed.append((pid, sig)),
        ),
    )
    monkeypatch.setattr(adapter, "signal", SimpleNamespace(SIGKILL=9))
    monkeypatch.setattr(
        adapter, "Path", lambda _path: SimpleNamespace(is_absolute=lambda: True)
    )
    monkeypatch.setattr(adapter.asyncio, "create_subprocess_exec", spawn)
    payload = {
        "schema_version": 1,
        "request_id": str(uuid.uuid4()),
        "conversation": "phantomview:" + "a" * 64,
        "question": "hello",
        "evidence": [],
    }
    with pytest.raises(ValueError, match="response exceeds bounds"):
        asyncio.run(
            adapter.ask_persona(
                payload,
                persona="agent",
                executable="/opt/bin/phantombot",
                expected_uid=123,
                cancelled=SimpleNamespace(is_set=lambda: False),
            )
        )
    assert killed and killed[0][0] == process.pid
