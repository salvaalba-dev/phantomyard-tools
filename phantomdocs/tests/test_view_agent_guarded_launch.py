import pytest

from phantomdocs.view_agent_guarded_launch import wait_ready


class Child:
    def __init__(self):
        self.killed = False
        self.waited = False

    def poll(self):
        return -9 if self.killed else None

    def kill(self):
        self.killed = True

    def wait(self, *, timeout):
        assert timeout == 5
        self.waited = True


def test_ready_child_remains_running():
    child = Child()
    wait_ready(child, lambda: True)
    assert not child.killed and not child.waited


def test_readiness_failure_kills_and_reaps_child():
    child = Child()

    def failed():
        raise OSError("Unavailable")

    with pytest.raises(OSError):
        wait_ready(child, failed)
    assert child.killed and child.waited


def test_timeout_kills_and_reaps_child(monkeypatch):
    child = Child()
    ticks = iter([0, 21])
    monkeypatch.setattr(
        "phantomdocs.view_agent_guarded_launch.time.monotonic", lambda: next(ticks)
    )
    with pytest.raises(RuntimeError):
        wait_ready(child, lambda: False)
    assert child.killed and child.waited
