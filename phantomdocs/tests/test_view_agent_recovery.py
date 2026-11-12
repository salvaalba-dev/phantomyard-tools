from contextlib import nullcontext

import pytest

from phantomdocs.view_agent_recovery import (
    RecoveryRequired,
    apply_route_change,
    recover_route_change,
)


class Host:
    def __init__(self):
        self.record = None
        self.revision = "r1"
        self.running = True
        self.content = b"old"
        self.good = True
        self.committed = (b"old", "r1")

    def lock(self):
        return nullcontext()

    def pending(self):
        return self.record

    def current_revision_is(self, revision):
        return revision == self.revision

    def validate(self, candidate):
        if candidate == b"bad":
            raise ValueError("Invalid")

    def write_journal(self, candidate, revision):
        self.record = (candidate, revision)

    def stop(self):
        self.running = False

    def replace(self, candidate):
        self.content = candidate

    def start(self):
        self.running = True

    def healthy(self):
        return self.good

    def clear_journal(self):
        self.record = None

    def write_committed(self, candidate, revision):
        self.committed = (candidate, revision)


def test_success_and_failed_restart_recover_without_old_grant():
    host = Host()
    host.good = False
    with pytest.raises(RecoveryRequired):
        apply_route_change(host, b"new", "r1")
    assert host.content == b"new" and not host.running and host.record
    host.good = True
    assert recover_route_change(host)
    assert host.running and host.content == b"new" and host.record is None
    assert host.committed == (b"new", "r1")


def test_binding_write_failure_stops_viewer_and_preserves_recovery():
    host = Host()

    def fail_commit(*_):
        raise OSError("disk full")

    host.write_committed = fail_commit
    with pytest.raises(RecoveryRequired):
        apply_route_change(host, b"new", "r1")
    assert not host.running and host.record == (b"new", "r1")
    assert host.committed == (b"old", "r1")


def test_stale_revision_never_restarts_previous_configuration():
    host = Host()
    host.record = (b"new", "r1")
    host.revision = "r2"
    with pytest.raises(RecoveryRequired):
        recover_route_change(host)
    assert not host.running and host.record is not None


def test_invalid_candidate_stops_running_viewer_without_journal():
    host = Host()
    with pytest.raises(RecoveryRequired):
        apply_route_change(host, b"bad", "r1")
    assert not host.running and host.record is None


def test_stale_authority_stops_running_viewer():
    host = Host()
    host.revision = "r2"
    with pytest.raises(RecoveryRequired):
        apply_route_change(host, b"new", "r1")
    assert not host.running and host.record is None


def test_unreadable_authority_stops_running_viewer():
    host = Host()

    def unreadable(_revision):
        raise OSError("authority unavailable")

    host.current_revision_is = unreadable
    with pytest.raises(RecoveryRequired):
        apply_route_change(host, b"new", "r1")
    assert not host.running and host.record is None


def test_unreadable_journal_stops_viewer():
    host = Host()

    def unreadable():
        raise ValueError("corrupt")

    host.pending = unreadable
    with pytest.raises(RecoveryRequired):
        recover_route_change(host)
    assert not host.running


def test_journal_write_failure_stops_viewer():
    host = Host()

    def fail_write(*_):
        raise OSError("disk full")

    host.write_journal = fail_write
    with pytest.raises(RecoveryRequired):
        apply_route_change(host, b"new", "r1")
    assert not host.running


def test_abrupt_exit_during_journal_write_leaves_viewer_stopped():
    host = Host()

    def interrupted(*_):
        raise SystemExit()

    host.write_journal = interrupted
    with pytest.raises(SystemExit):
        apply_route_change(host, b"new", "r1")
    assert not host.running
