"""Synthetic socket activation checks; no real systemd unit is installed."""

import os
import socket
import stat
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from phantomdocs import workflow_admission_activation as activation_admission
from phantomdocs.workflow_policy_guard import PolicyRecoveryRequired


class Listener:
    family = 1
    type = socket.SOCK_STREAM

    def __init__(self):
        self.path = "/run/example/admission.sock"
        self.accepting = 1
        self.closed = False

    def getsockopt(self, *_):
        return self.accepting

    def getsockname(self):
        return self.path

    def close(self):
        self.closed = True


@pytest.fixture
def activation(monkeypatch):
    @contextmanager
    def parent(_path):
        yield 12, "admission.sock"

    entry = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
    listener = Listener()
    monkeypatch.setattr(activation_admission.sys, "platform", "linux")
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(activation_admission, "protected_parent", parent)
    monkeypatch.setattr(activation_admission.os, "stat", lambda *_a, **_k: entry)
    monkeypatch.setattr(socket, "fromfd", lambda *_: listener)
    return entry, listener, {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1"}


def test_accepts_only_the_expected_activated_socket(activation):
    _, listener, env = activation
    assert (
        activation_admission.validated_systemd_socket(listener.path, environ=env)
        is listener
    )


@pytest.mark.parametrize("field,value", [("LISTEN_PID", "0"), ("LISTEN_FDS", "2")])
def test_rejects_invalid_activation_environment(activation, field, value):
    _, listener, env = activation
    env[field] = value
    with pytest.raises(ValueError, match="activated"):
        activation_admission.validated_systemd_socket(listener.path, environ=env)


@pytest.mark.parametrize(
    "mode,uid",
    [
        (stat.S_IFLNK | 0o777, 0),
        (stat.S_IFSOCK | 0o666, 0),
        (stat.S_IFSOCK | 0o660, 123),
    ],
)
def test_rejects_untrusted_socket_file(activation, mode, uid):
    entry, listener, env = activation
    entry.st_mode, entry.st_uid = mode, uid
    with pytest.raises(ValueError, match="protected"):
        activation_admission.validated_systemd_socket(listener.path, environ=env)


@pytest.mark.parametrize(
    "attribute,value", [("path", "/run/other.sock"), ("accepting", 0)]
)
def test_closes_wrong_listener(activation, attribute, value):
    _, listener, env = activation
    setattr(listener, attribute, value)
    with pytest.raises(ValueError, match="unexpected"):
        activation_admission.validated_systemd_socket(
            "/run/example/admission.sock", environ=env
        )
    assert listener.closed


def test_listener_survives_pending_recovery_but_does_not_mask_other_errors(monkeypatch):
    calls = []

    def serve(listener, config, *, expected_socket):
        calls.append((listener, config, expected_socket))
        if len(calls) == 1:
            raise PolicyRecoveryRequired("synthetic pending update")
        raise RuntimeError("synthetic unrelated failure")

    monkeypatch.setattr(activation_admission, "serve_configured_once", serve)
    listener = object()
    with pytest.raises(RuntimeError, match="unrelated"):
        activation_admission.serve_forever(listener, "/etc/config", "/run/socket")
    assert calls == [(listener, "/etc/config", "/run/socket")] * 2
