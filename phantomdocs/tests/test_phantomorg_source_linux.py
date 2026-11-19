"""Real protected source replacement and fanout, with synthetic identities only."""

import copy
import json
import os
import subprocess
import sys
import threading

import pytest
from source_publication_fixture import snapshots
from test_policy_fanout_linux import trial as trial  # noqa: PLC0414 -- pytest fixture

from phantomdocs import workflow_bridge_policy as publisher
from phantomdocs import workflow_policy_fanout as journal
from phantomdocs.access import can_read
from phantomdocs.manifest import empty_manifest, save
from phantomdocs.view_matrix_authority import guarded_matrix_authority
from phantomdocs.workflow_policy_guard import PolicyRecoveryRequired
from phantomdocs.workflow_policy_sync import policy_permissions

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="requires Linux root and protected synthetic paths",
)


@pytest.fixture
def source_trial(trial):
    paths, state, options = trial
    old, new = snapshots()
    for name in ("source", "bridge", "docs"):
        paths[name].write_bytes(old)
    paths["source"].chmod(0o644)
    candidate = paths["source"].parent / "candidate"
    candidate.write_bytes(new)
    candidate.chmod(0o600)
    paths["candidate"] = candidate
    reviewed = dict(
        options,
        candidate=str(candidate),
        expected_source_sha256=journal.digest(old),
        candidate_sha256=journal.digest(new),
        organization="sample-org",
    )
    return paths, state, options, reviewed


@pytest.mark.parametrize("fail_at", [1, 2, 3])
def test_source_and_destinations_recover_with_actual_consumer_revocation(
    source_trial, monkeypatch, fail_at
):
    paths, _, options, reviewed = source_trial
    os.chown(paths["docs"], 0, 65533)
    subprocess.run(["setfacl", "-m", "u:65534:r--", str(paths["docs"])], check=True)
    os.setxattr(paths["source"], "user.synthetic-source", b"preserve")
    baseline = {
        name: policy_permissions(str(paths[name]))
        for name in ("source", "bridge", "docs")
    }
    sync = publisher._synchronize_locked
    calls = 0

    def interrupted(*args, **kw):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise OSError("synthetic source transaction interruption")
        sync(*args, **kw)

    monkeypatch.setattr(publisher, "_synchronize_locked", interrupted)
    manifest = str(paths["docs"].parent / "manifest.yaml")
    save(manifest, empty_manifest("sample-org", "docs", "a" * 64))

    def authority():
        return guarded_matrix_authority(
            policy_lock=options["lock_path"],
            org_path=str(paths["docs"]),
            native_manifest=manifest,
            reader=lambda *args: None,
        )

    with authority() as (org, _, _):
        assert can_read(org, "agent", "category-1")
    with pytest.raises(OSError, match="interruption"):
        publisher.refresh(**reviewed)
    with pytest.raises(PolicyRecoveryRequired):  # noqa: SIM117
        with authority():
            pytest.fail("reader used a source/copy mixture")
    paths["candidate"].unlink()
    monkeypatch.setattr(publisher, "_synchronize_locked", sync)
    assert publisher.refresh(**options) == "restarted"
    assert journal.read_pending(options["lock_path"]) is None
    assert {name: policy_permissions(str(paths[name])) for name in baseline} == baseline
    assert all(paths[n].read_bytes() == snapshots()[1] for n in baseline)
    with authority() as (org, _, _):
        assert not can_read(org, "agent", "category-1")


def test_process_death_after_source_rename_recovers_from_pinned_bytes(source_trial):
    paths, _, options, reviewed = source_trial
    code = """
import json,os,sys
from phantomdocs import workflow_bridge_policy as p
p._derive_both=lambda a,b,**kw:(a,b)
p._systemctl=lambda action,unit:True
sync=p._synchronize_locked
def killed(*args,**kw):
    sync(*args,**kw)
    os._exit(93)
p._synchronize_locked=killed
p.refresh(**json.loads(sys.argv[1]))
"""
    completed = subprocess.run(
        [sys.executable, "-B", "-c", code, json.dumps(reviewed)], check=False
    )
    assert completed.returncode == 93
    assert paths["source"].read_bytes() == snapshots()[1]
    assert paths["bridge"].read_bytes() == snapshots()[0]
    paths["candidate"].unlink()
    assert publisher.refresh(**options) == "restarted"
    assert all(
        paths[n].read_bytes() == snapshots()[1] for n in ("source", "bridge", "docs")
    )


def test_two_reviewed_writers_cannot_overwrite_each_other(source_trial, monkeypatch):
    paths, state, _, first = source_trial
    other_candidate = paths["source"].parent / "other-candidate"
    other = snapshots()[1].replace(b"Sample organization", b"Other reviewed name")
    assert other != snapshots()[1]
    other_candidate.write_bytes(other)
    other_candidate.chmod(0o600)
    second = dict(
        first, candidate=str(other_candidate), candidate_sha256=journal.digest(other)
    )
    entered, release, second_started = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    sync = publisher._synchronize_locked

    def paused(src, dst, **kw):
        if dst == str(paths["source"]) and not entered.is_set():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("synthetic concurrency timeout")
        return sync(src, dst, **kw)

    monkeypatch.setattr(publisher, "_synchronize_locked", paused)
    errors = []

    def run(args, signal=False):
        if signal:
            second_started.set()
        try:
            publisher.refresh(**args)
        except Exception as exc:  # noqa: BLE001 -- collect thread failures
            errors.append(exc)

    one = threading.Thread(target=run, args=(copy.copy(first),))
    two = threading.Thread(target=run, args=(copy.copy(second), True))
    one.start()
    try:
        assert entered.wait(3)
        two.start()
        assert second_started.wait(3)
    finally:
        release.set()
        one.join(8)
        if two.ident is not None:
            two.join(8)
    assert not one.is_alive() and not two.is_alive()
    assert len(errors) == 1 and "stale" in str(errors[0])
    assert paths["source"].read_bytes() == snapshots()[1]
    assert state["active"]
