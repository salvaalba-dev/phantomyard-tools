import os
import tempfile
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from phantomdocs import view_matrix_drive as drive


def test_reads_as_expected_local_agent_and_limits_size(monkeypatch):
    uid = 123
    real_fstat = os.fstat

    def fake_fstat(fd):
        info = real_fstat(fd)
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_uid=uid,
            st_nlink=1,
            st_size=info.st_size,
            st_mtime_ns=info.st_mtime_ns,
            st_ctime_ns=info.st_ctime_ns,
        )

    monkeypatch.setattr(
        drive, "os", SimpleNamespace(name="posix", getuid=lambda: uid, fstat=fake_fstat)
    )

    @contextmanager
    def temporary_file(**kwargs):
        with (
            tempfile.TemporaryDirectory() as directory,
            open(os.path.join(directory, "output"), "w+b") as stream,
        ):
            yield stream

    monkeypatch.setattr(
        drive, "tempfile", SimpleNamespace(NamedTemporaryFile=temporary_file)
    )

    def run(args, **kwargs):
        assert args[:3] == ["/workspace", "drive", "download"]
        with open(args[-1], "wb") as output:
            output.write(b"content")

    monkeypatch.setattr(drive.subprocess, "run", run)
    args = {
        "ref": "gdrive://abcdefghij",
        "workspace": "/workspace",
        "expected_uid": uid,
    }
    assert drive.read_workspace(limit=16, **args) == b"content"
    with pytest.raises(ValueError):
        drive.read_workspace(limit=3, **args)
    with pytest.raises(ValueError):
        drive.read_workspace(limit=16, **{**args, "expected_uid": 124})
