"""Address selection and TLS tests use synthetic sockets and never send traffic."""

import shutil
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path
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
    context = SimpleNamespace(wrap_socket=lambda sock, server_hostname: sock)
    connected = adapter.connect_ipv4_first("example.invalid", 443, 20, context)
    assert seen[0].family == socket.AF_INET
    assert 0 < seen[0].timeouts[0] <= 3
    assert connected is seen[-1]
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
            adapter.connect_ipv4_first("example.invalid", 443, 0.03, None)
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
        adapter.connect_ipv4_first("example.invalid", 443, 20, None)
    assert closed == [socket.AF_INET, socket.AF_INET6]


@pytest.mark.parametrize("certificate_failure", [False, True])
def test_tls_timeout_can_fallback_but_certificate_failure_cannot(
    monkeypatch, certificate_failure
):
    addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0)),
    ]
    monkeypatch.setattr(adapter.socket, "getaddrinfo", lambda *args: addresses)
    seen = []

    class FakeSocket:
        def __init__(self, family, *_):
            self.family = family
            self.closed = False
            seen.append(self)

        def settimeout(self, timeout):
            assert timeout > 0

        def connect(self, address):
            pass

        def close(self):
            self.closed = True

    monkeypatch.setattr(adapter.socket, "socket", FakeSocket)

    def wrap(sock, *, server_hostname):
        assert server_hostname == "api.telegram.org"
        if sock.family == socket.AF_INET:
            if certificate_failure:
                raise adapter.ssl.SSLCertVerificationError(
                    "synthetic invalid certificate"
                )
            raise TimeoutError("synthetic TLS timeout")
        return sock

    context = SimpleNamespace(wrap_socket=wrap)
    if certificate_failure:
        with pytest.raises(adapter.ssl.SSLCertVerificationError):
            adapter.connect_ipv4_first("api.telegram.org", 443, 20, context)
        assert len(seen) == 1 and seen[0].closed
    else:
        result = adapter.connect_ipv4_first("api.telegram.org", 443, 20, context)
        assert len(seen) == 2 and seen[0].closed
        assert result is seen[1] and result.family == socket.AF_INET6


@pytest.mark.skipif(
    shutil.which("openssl") is None or adapter.tomllib is None,
    reason="OpenSSL and Python 3.11+ required for the local TLS fixture",
)
def test_real_https_handler_verifies_hostname_and_sends_once_to_loopback(
    tmp_path, monkeypatch
):
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=api.telegram.org",
            "-addext",
            "subjectAltName=DNS:api.telegram.org",
        ],
        check=True,
        capture_output=True,
        timeout=20,
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(cert), str(key))
    sni, received, failures = [], [], []
    server_context.set_servername_callback(lambda sock, name, ctx: sni.append(name))

    def serve():
        try:
            raw, _ = listener.accept()
            with server_context.wrap_socket(raw, server_side=True) as connection:
                connection.settimeout(5)
                data = b""
                while b"\r\n\r\n" not in data:
                    data += connection.recv(4096)
                headers, body = data.split(b"\r\n\r\n", 1)
                length = next(
                    int(line.split(b":", 1)[1])
                    for line in headers.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                )
                while len(body) < length:
                    body += connection.recv(4096)
                received.append((headers, body))
                response = b'{"ok":true,"result":{"message_id":42,"date":1700000000,"chat":{"id":10001,"type":"private"}}}'
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(response)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + response
                )
        except (OSError, ValueError, StopIteration) as error:
            failures.append(error)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr(
        adapter.socket,
        "getaddrinfo",
        lambda *args: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
        ],
    )
    context = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(adapter.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(
        adapter,
        "read_file",
        lambda *args, **kwargs: (
            b'[channels.telegram]\ntoken="123456:AAAAAAAAAAAAAAAAAAAAAAAA"\nallowed_user_ids=[10001]\n'
        ),
    )
    try:
        assert adapter.telegram(Path("/synthetic"), 1001, "10001", "test") == (
            "42",
            1700000000,
        )
    finally:
        thread.join(6)
        listener.close()
    assert not thread.is_alive() and not failures
    assert sni == ["api.telegram.org"] and len(received) == 1
    assert received[0][0].startswith(b"POST /bot")
