"""Real lock-inode receipt writes and interrupted bootstrap on synthetic Linux paths."""

import json
import os
import sys

import pytest
from test_policy_fanout_linux import trial as trial  # noqa: PLC0414 -- pytest fixture

from phantomdocs import workflow_bridge_policy as publisher
from phantomdocs import workflow_policy_commit as committed
from phantomdocs.workflow_policy_guard import PolicyRecoveryRequired, policy_guard
from phantomdocs.workflow_policy_sync import policy_permissions

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="requires Linux root and protected synthetic paths",
)


def test_receipt_changes_neither_inode_nor_permissions_and_binds_source(trial):
    paths, _, options = trial
    lock = options["lock_path"]
    before = os.stat(lock)
    os.setxattr(lock, "user.synthetic-receipt", b"preserve")
    permissions = policy_permissions(lock)
    assert publisher.refresh(**options, commit_witness=True) == "restarted"
    assert os.stat(lock).st_ino == before.st_ino
    assert policy_permissions(lock) == permissions
    with committed.committed_guard(lock, str(paths["source"])) as value:
        assert value == committed.receipt(
            str(paths["source"]), paths["source"].read_bytes()
        )
    with pytest.raises(ValueError):  # noqa: SIM117 -- explicit denial boundary
        with committed.committed_guard(lock, "/another/source"):
            pytest.fail("wrong source accepted")


def test_bootstrap_torn_write_keeps_marker_until_the_same_runtime_recovers(
    trial, monkeypatch
):
    paths, state, options = trial
    payload = paths["source"].read_bytes()
    paths["bridge"].write_bytes(payload)
    paths["docs"].write_bytes(payload)
    write = publisher.write_committed_locked

    def interrupted(lock, *args):
        with open(lock, "wb") as stream:
            stream.write(b'{"kind":')
            stream.flush()
            os.fsync(stream.fileno())
        raise OSError("synthetic process interruption")

    monkeypatch.setattr(publisher, "write_committed_locked", interrupted)
    with pytest.raises(OSError):
        publisher.refresh(**options, commit_witness=True)
    with pytest.raises(PolicyRecoveryRequired):  # noqa: SIM117 -- explicit denial boundary
        with committed.committed_guard(options["lock_path"], str(paths["source"])):
            pytest.fail("torn receipt authorized")
    monkeypatch.setattr(publisher, "write_committed_locked", write)
    assert publisher.refresh(**options, commit_witness=True) == "restarted"
    assert state["active"]
    assert json.loads(paths["lock"].read_bytes())["sha256"] == committed.digest(payload)


@pytest.mark.parametrize("raw", [b"foreign lock contents", b"{}", b'{"kind":'])
def test_unowned_contents_cannot_be_silently_bootstrapped(trial, raw):
    paths, _, options = trial
    paths["lock"].write_bytes(raw)
    with pytest.raises(ValueError):
        publisher.refresh(**options, commit_witness=True)
    assert paths["lock"].read_bytes() == raw
    assert not paths["lock"].with_name("lock.pending").exists()


def test_lock_timeout_is_bounded_and_does_not_change_its_contents(trial):
    paths, _, options = trial
    lock = options["lock_path"]
    with policy_guard(lock, exclusive=True), pytest.raises(TimeoutError):  # noqa: SIM117
        with policy_guard(lock, exclusive=False, timeout=0.02):
            pytest.fail("reader acquired a held exclusive lock")
    assert paths["lock"].read_bytes() == b""


def test_active_receipt_cannot_be_disabled_by_an_omitted_flag_or_ordinary_writer(trial):
    paths, _, options = trial
    publisher.refresh(**options, commit_witness=True)
    value = paths["lock"].read_bytes()
    assert publisher.refresh(**options) == "synchronized"
    assert paths["lock"].read_bytes() == value
    with pytest.raises(PolicyRecoveryRequired):  # noqa: SIM117
        with policy_guard(options["lock_path"], exclusive=True):
            pytest.fail("ordinary writer bypassed committed protocol")


def test_strict_reconcile_does_not_bless_a_manual_source_edit(trial):
    paths, state, options = trial
    publisher.refresh(**options, commit_witness=True)
    before = {name: paths[name].read_bytes() for name in ("bridge", "docs", "lock")}
    paths["source"].write_bytes(b"version: 1\nmanual: true\n")
    with pytest.raises(ValueError, match="receipt"):
        publisher.refresh(**options, require_committed_source=True)
    assert {name: paths[name].read_bytes() for name in before} == before
    assert not state["active"]
    assert not paths["lock"].with_name("lock.pending").exists()


def test_strict_bootstrap_requires_review_and_preserves_metadata(trial):
    paths, _, options = trial
    before = {
        name: policy_permissions(str(paths[name]))
        for name in ("source", "bridge", "docs")
    }
    reviewed = committed.digest(paths["source"].read_bytes())
    with pytest.raises(ValueError, match="receipt"):
        publisher.refresh(**options, require_committed_source=True)
    assert (
        publisher.refresh(
            **options, require_committed_source=True, bootstrap_source_sha256=reviewed
        )
        == "synchronized"
    )
    assert {name: policy_permissions(str(paths[name])) for name in before} == before
    with committed.committed_guard(options["lock_path"], str(paths["source"])) as value:
        assert value["sha256"] == reviewed
