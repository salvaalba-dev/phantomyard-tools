"""Privileged synthetic filesystem acceptance; never uses installed policy paths."""

import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from phantomdocs import workflow_bridge_policy as publisher
from phantomdocs import workflow_policy_fanout as journal
from phantomdocs.manifest import empty_manifest, save
from phantomdocs.view_matrix_authority import guarded_matrix_authority
from phantomdocs.workflow_policy_guard import PolicyRecoveryRequired, policy_guard
from phantomdocs.workflow_policy_sync import policy_permissions, synchronize
from phantomdocs.workflow_policy_watchdog import check

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="requires Linux root and protected synthetic paths",
)


@pytest.fixture
def trial(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="policy-fanout-", dir="/var/lib") as folder:
        root = Path(folder)
        root.chmod(0o711)
        paths = {
            name: root / name
            for name in ("source", "bridge", "docs", "lock", "lock.publisher")
        }
        for name in ("source", "bridge", "docs"):
            paths[name].write_text(
                "version: 1\nvalue: " + ("new" if name == "source" else "old") + "\n"
            )
        paths["bridge"].chmod(0o600)
        paths["docs"].chmod(0o640)
        for name in ("lock", "lock.publisher"):
            paths[name].touch(mode=0o600)
        state = {"active": True, "actions": []}

        def control(action, unit):
            state["actions"].append(action)
            if action == "is-active":
                return state["active"]
            state["active"] = action == "start"
            return True

        monkeypatch.setattr(publisher, "_systemctl", control)
        monkeypatch.setattr(publisher, "_derive_both", lambda a, b, **kw: (a, b))
        options = {
            "source": str(paths["source"]),
            "destination": [str(paths["bridge"]), str(paths["docs"])],
            "lock_path": str(paths["lock"]),
            "resolver": "/synthetic/resolver.js",
            "node": "/usr/bin/node",
            "unit": "synthetic.service",
        }
        yield paths, state, options


def test_atomic_fanout_preserves_named_acl_mode_owner_and_actual_reader_access(trial):
    paths, _, options = trial
    assert shutil.which("setfacl") and shutil.which("getfacl"), (
        "install ACL tools for acceptance"
    )
    os.chown(paths["docs"], 0, 65533)
    subprocess.run(["setfacl", "-m", "u:65534:r--", str(paths["docs"])], check=True)
    os.setxattr(paths["docs"], "user.synthetic-policy", b"keep")
    before = {name: policy_permissions(str(paths[name])) for name in ("bridge", "docs")}
    acl = subprocess.check_output(["getfacl", "-cpn", str(paths["docs"])])
    # Temporary files must not inherit additional access from a directory's
    # default ACL. Only the destination's captured ACL may survive replacement.
    subprocess.run(
        ["setfacl", "-m", "d:u:65532:r--", str(paths["docs"].parent)], check=True
    )

    def read_as(uid, path):
        return subprocess.run(
            [
                "/usr/bin/python3",
                "-B",
                "-c",
                "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())",
                str(path),
            ],
            user=uid,
            group=65534,
            extra_groups=[],
            capture_output=True,
            check=False,
        )

    assert read_as(65534, paths["docs"]).returncode == 0
    assert read_as(65534, paths["bridge"]).returncode != 0
    assert publisher.refresh(**options) == "restarted"
    assert {name: policy_permissions(str(paths[name])) for name in before} == before
    assert subprocess.check_output(["getfacl", "-cpn", str(paths["docs"])]) == acl
    assert read_as(65534, paths["docs"]).stdout == paths["source"].read_bytes()
    assert read_as(65534, paths["bridge"]).returncode != 0
    assert (
        check(**{k: options[k] for k in ("source", "destination", "lock_path")})[
            "status"
        ]
        == "ok"
    )


@pytest.mark.parametrize("failure_at", [1, 2])
def test_interrupted_copy_blocks_actual_consumer_and_break_glass_until_retry(
    trial, monkeypatch, failure_at
):
    paths, state, options = trial
    sync = publisher._synchronize_locked
    calls = 0

    def fail(source, destination, **kw):
        nonlocal calls
        calls += 1
        if calls == failure_at:
            raise OSError("synthetic interruption")
        sync(source, destination, **kw)

    monkeypatch.setattr(publisher, "_synchronize_locked", fail)
    with pytest.raises(OSError, match="interruption"):
        publisher.refresh(**options)
    record = journal.read_pending(options["lock_path"])
    assert record is not None and not state["active"]
    manifest = str(paths["docs"].parent / "manifest.yaml")
    save(manifest, empty_manifest("synthetic", "docs", "a" * 64))
    with pytest.raises(PolicyRecoveryRequired):  # noqa: SIM117
        with guarded_matrix_authority(
            policy_lock=options["lock_path"],
            org_path=str(paths["docs"]),
            native_manifest=manifest,
            reader=lambda *a: None,
        ):
            pytest.fail("consumer used a partially published revision")
    with pytest.raises(PolicyRecoveryRequired):
        synchronize(options["source"], str(paths["docs"]), options["lock_path"])
    assert journal.read_pending(options["lock_path"]) == record
    monkeypatch.setattr(publisher, "_synchronize_locked", sync)
    assert publisher.refresh(**options) == "restarted"
    assert journal.read_pending(options["lock_path"]) is None
    with guarded_matrix_authority(
        policy_lock=options["lock_path"],
        org_path=str(paths["docs"]),
        native_manifest=manifest,
        reader=lambda *a: None,
    ) as (org, _, _):
        assert org["value"] == "new"


def test_readers_serialize_before_all_destination_writes(trial):
    paths, _, options = trial
    started, completed = threading.Event(), threading.Event()
    errors = []

    def publish():
        started.set()
        try:
            publisher.refresh(**options)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            completed.set()

    with policy_guard(options["lock_path"], exclusive=False):
        worker = threading.Thread(target=publish)
        worker.start()
        assert started.wait(3)
        assert not completed.wait(0.2)
        assert b"old" in paths["bridge"].read_bytes()
        assert b"old" in paths["docs"].read_bytes()
    worker.join(5)
    assert not worker.is_alive() and not errors
    assert (
        paths["bridge"].read_bytes()
        == paths["docs"].read_bytes()
        == paths["source"].read_bytes()
    )


@pytest.mark.parametrize(
    "unsafe", ["symlink", "hardlink", "unreadable", "invalid", "duplicate"]
)
def test_unsafe_input_does_not_replace_any_destination(trial, unsafe):
    paths, _, options = trial
    before = paths["docs"].read_bytes()
    if unsafe == "symlink":
        paths["bridge"].unlink()
        paths["bridge"].symlink_to(paths["source"])
    elif unsafe == "hardlink":
        paths["bridge"].unlink()
        os.link(paths["source"], paths["bridge"])
    elif unsafe == "unreadable":
        paths["source"].unlink()
    elif unsafe == "invalid":
        paths["source"].write_text("version: 9\n")
    else:
        paths["source"].write_text("version: 1\nvalue: one\nvalue: two\n")
    with pytest.raises((OSError, ValueError)):
        publisher.refresh(**options)
    assert paths["docs"].read_bytes() == before
    assert journal.read_pending(options["lock_path"]) is None


def test_killed_process_after_first_rename_is_recovered_from_disk(trial):
    paths, _, options = trial
    # Terminate a separate process after an actual successful replacement. The
    # next invocation must use the durable journal, not any Python memory state.
    script = """
import json,os,sys
from phantomdocs import workflow_bridge_policy as p
p._derive_both=lambda a,b,**kw:(a,b)
p._systemctl=lambda action,unit:True
sync=p._synchronize_locked
def killed(*args,**kw):
    sync(*args,**kw)
    os._exit(91)
p._synchronize_locked=killed
p.refresh(**json.loads(sys.argv[1]))
"""
    import json

    result = subprocess.run(
        [sys.executable, "-B", "-c", script, json.dumps(options)], check=False
    )
    assert result.returncode == 91
    assert paths["bridge"].read_bytes() == paths["source"].read_bytes()
    assert paths["docs"].read_bytes() != paths["source"].read_bytes()
    assert journal.read_pending(options["lock_path"]) is not None
    assert publisher.refresh(**options) == "restarted"
    assert journal.read_pending(options["lock_path"]) is None


def test_foreign_marker_is_not_overwritten(trial):
    paths, _, options = trial
    pending = Path(options["lock_path"] + ".pending")
    pending.write_text('{"source":"manual-publication"}')
    pending.chmod(0o600)
    with pytest.raises(ValueError, match="pending"):
        publisher.refresh(**options)
    assert pending.read_text() == '{"source":"manual-publication"}'
    assert b"old" in paths["bridge"].read_bytes()
