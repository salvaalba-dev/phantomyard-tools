"""Policy publication must preserve backups and fail closed after interruption."""

import hashlib
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from phantomdocs import workflow_policy_publish as publication
from phantomdocs.workflow_policy_guard import policy_guard

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root and protected paths",
)


@pytest.fixture
def files():
    with tempfile.TemporaryDirectory(dir="/root") as directory:
        paths = {
            name: Path(directory) / name
            for name in ("candidate", "source", "destination", "backup", "lock")
        }
        for name in ("source", "destination", "backup"):
            paths[name].write_text("version: 1\nold: true\n")
        paths["candidate"].write_text("version: 1\nnew: true\n")
        paths["lock"].touch(mode=0o600)
        yield paths


def call_publish(files, expected=None):
    digest = hashlib.sha256(files["source"].read_bytes()).hexdigest()
    publication.publish(
        *(
            str(files[name])
            for name in ("candidate", "source", "destination", "backup", "lock")
        ),
        expected or digest,
    )


def test_publication_preserves_backup_and_releases_readers(files):
    call_publish(files)
    assert (
        files["source"].read_bytes()
        == files["destination"].read_bytes()
        == files["candidate"].read_bytes()
    )
    assert files["backup"].read_text() == "version: 1\nold: true\n"
    with policy_guard(str(files["lock"]), exclusive=False):
        pass


def test_stale_base_and_nonindependent_backup_are_rejected(files):
    with pytest.raises(ValueError, match="changed"):
        call_publish(files, "0" * 64)
    files["destination"].write_text("version: 1\nother: true\n")
    with pytest.raises(ValueError, match="changed"):
        call_publish(files)
    assert files["source"].read_text() == "version: 1\nold: true\n"
    files["destination"].write_bytes(files["source"].read_bytes())
    files["backup"].unlink()
    os.link(files["source"], files["backup"])
    with pytest.raises(ValueError):
        call_publish(files)


def test_interrupted_publication_denies_reads_until_recovery(files):
    original = publication._synchronize_locked
    calls = []

    def fail_second(*args, **kwargs):
        calls.append(True)
        if len(calls) == 2:
            raise OSError("synthetic interruption")
        return original(*args, **kwargs)

    with patch.object(publication, "_synchronize_locked", side_effect=fail_second):  # noqa: SIM117
        with pytest.raises(OSError, match="interruption"):
            call_publish(files)
    assert files["source"].read_bytes() == files["candidate"].read_bytes()
    assert files["destination"].read_bytes() == files["backup"].read_bytes()
    with pytest.raises(ValueError, match="recovery"):  # noqa: SIM117
        with policy_guard(str(files["lock"]), exclusive=False):
            pass
    publication.recover(
        str(files["source"]), str(files["destination"]), str(files["lock"])
    )
    assert files["source"].read_bytes() == files["destination"].read_bytes()
    with policy_guard(str(files["lock"]), exclusive=False):
        pass


def test_invalid_candidate_and_missing_backup_do_not_change_policy(files):
    files["candidate"].write_text("version: 9\n")
    with pytest.raises(ValueError):
        call_publish(files)
    assert files["source"].read_bytes() == files["destination"].read_bytes()
    assert not files["lock"].with_name("lock.pending").exists()
    files["backup"].unlink()
    with pytest.raises(OSError):
        call_publish(files)


def test_concurrent_source_change_is_not_overwritten(files):
    original = publication._synchronize_locked

    def change_source(*args, **kwargs):
        files["source"].write_text("version: 1\nother: true\n")
        return original(*args, **kwargs)

    with patch.object(publication, "_synchronize_locked", side_effect=change_source):  # noqa: SIM117
        with pytest.raises(ValueError, match="destination policy changed"):
            call_publish(files)
    assert files["source"].read_text() == "version: 1\nother: true\n"
    assert files["backup"].read_text() == "version: 1\nold: true\n"
    with pytest.raises(ValueError, match="recovery"):  # noqa: SIM117
        with policy_guard(str(files["lock"]), exclusive=False):
            pass
