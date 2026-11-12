from contextlib import nullcontext

import pytest

from phantomdocs.view_agent_recovery import RecoveryRequired
from phantomdocs.view_agent_supervisor import reconcile_once


class Host:
    def __init__(self):
        self.revision = "r1"
        self.content = b"old"
        self.committed = (b"old", "r1")
        self.record = None
        self.running = True
        self.stops = 0

    def lock(self):
        return nullcontext()

    def pending(self):
        return self.record

    def authority(self):
        return b"org", self.revision

    def current_revision_is(self, revision):
        return self.revision == revision

    def committed_revision_is(self, revision):
        return self.committed == (self.content, revision)

    def configuration_is_committed(self, candidate, revision):
        return self.committed == (candidate, revision) and self.content == candidate

    def validate(self, _candidate):
        pass

    def stop(self):
        self.stops += 1
        self.running = False

    def start(self):
        self.running = True

    def healthy(self):
        return self.running

    def write_journal(self, candidate, revision):
        self.record = (candidate, revision)

    def replace(self, candidate):
        self.content = candidate

    def write_committed(self, candidate, revision):
        self.committed = (candidate, revision)

    def clear_journal(self):
        self.record = None


def test_unchanged_viewer_is_not_restarted():
    host = Host()
    assert reconcile_once(host, lambda _: b"old") == "unchanged"
    assert host.running and host.stops == 0


def test_revocation_stops_old_viewer_before_building_new_routes():
    host = Host()
    host.revision = "r2"

    def build(_org):
        assert not host.running
        return b"revoked-route-removed"

    assert reconcile_once(host, build) == "updated"
    assert host.running and host.committed == (b"revoked-route-removed", "r2")


def test_recovery_requires_freshly_verified_matching_candidate():
    host = Host()
    host.record = (b"new", "r1")
    assert reconcile_once(host, lambda _: b"new") == "recovered"
    assert host.running and host.record is None
    host.record = (b"old-identity", "r1")
    with pytest.raises(RecoveryRequired):
        reconcile_once(host, lambda _: b"new-identity")
    assert not host.running and host.record == (b"old-identity", "r1")


def test_failed_identity_probe_stops_viewer():
    host = Host()

    def fail(_org):
        raise OSError("identity probe failed")

    with pytest.raises(RecoveryRequired):
        reconcile_once(host, fail)
    assert not host.running


def test_failed_lock_stops_viewer():
    host = Host()

    def fail():
        raise OSError("lock unavailable")

    host.lock = fail
    with pytest.raises(RecoveryRequired):
        reconcile_once(host, lambda _: b"old")
    assert not host.running
