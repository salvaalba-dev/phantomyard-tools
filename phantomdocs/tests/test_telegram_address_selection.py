"""Address selection and TLS tests use synthetic sockets and never send traffic."""

import socket
import threading
import time
from types import SimpleNamespace

import pytest

from phantomdocs import notify_adapter as adapter


@pytest.mark.parametrize("ipv4_fails", [False, True])
def test_ipv4_precedes_ipv6_and_failed_sockets_are_closed(monkeypatch, ipv4_fails):
    ipv6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0))
    ipv4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))
    monkeypatch.setattr(adapter.socket, "getaddrinfo", lambda *args: [ipv6, ipv4, ipv4])
    seen = []

    class FakeSocket:
        def __init__(self, family, *_):
            self.family = family
            self.closed = False
            self.timeouts = []
            seen.append(self)

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

        def connect(self, address):
            if self.family == socket.AF_INET and ipv4_fails:
                raise TimeoutError("synthetic connection timeout")

        def close(self):
            self.closed = True

    monkeypatch.setattr(adapter.socket, "socket", FakeSocket)
    connected, deadline = adapter.connect_ipv4_first("example.invalid", 443, 20)
    assert seen[0].family == socket.AF_INET
    assert 0 < seen[0].timeouts[0] <= 3
    assert connected is seen[-1] and deadline > time.monotonic()
    if ipv4_fails:
        assert len(seen) == 2 and seen[0].closed
        assert seen[1].family == socket.AF_INET6
    else:
        assert len(seen) == 1


def test_stalled_dns_does_not_block_the_connection_budget(monkeypatch):
    finished = threading.Event()
    monkeypatch.setattr(adapter.socket, "getaddrinfo", lambda *a: finished.wait(1))
    try:
        start = time.monotonic()
        with pytest.raises(TimeoutError, match="resolution"):
            adapter.connect_ipv4_first("example.invalid", 443, 0.03)
        assert time.monotonic() - start < 0.5
    finally:
        finished.set()


def test_all_addresses_failing_closes_each_socket(monkeypatch):
    addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0)),
    ]
    monkeypatch.setattr(adapter.socket, "getaddrinfo", lambda *args: addresses)
    closed = []

    class FailedSocket:
        def __init__(self, family, *_):
            self.family = family

        def settimeout(self, timeout):
            assert 0 < timeout <= 3

        def connect(self, address):
            raise OSError("synthetic failure")

        def close(self):
            closed.append(self.family)

    monkeypatch.setattr(adapter.socket, "socket", FailedSocket)
    with pytest.raises(OSError, match="synthetic failure"):
        adapter.connect_ipv4_first("example.invalid", 443, 20)
    assert closed == [socket.AF_INET, socket.AF_INET6]


def test_tls_uses_original_hostname_and_does_not_retry_after_failure(monkeypatch):
    calls = []
    raw = SimpleNamespace(close=lambda: calls.append("closed"))
    monkeypatch.setattr(
        adapter, "connect_ipv4_first", lambda *a: (raw, time.monotonic() + 10)
    )

    def fail_tls(sock, *, server_hostname):
        calls.append(server_hostname)
        raise adapter.ssl.SSLError("synthetic TLS failure")

    connection = adapter.IPv4FirstHTTPSConnection("api.telegram.org", timeout=20)
    connection._context = SimpleNamespace(wrap_socket=fail_tls)
    with pytest.raises(adapter.ssl.SSLError):
        connection.connect()
    assert calls == ["api.telegram.org", "closed"]
