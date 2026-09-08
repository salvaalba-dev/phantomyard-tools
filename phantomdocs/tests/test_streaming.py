"""Large-file tests check bounded reads and allocations, not timing."""

import hashlib
import io
import shutil
import sys
import tracemalloc
from unittest import mock

import pytest

from phantomdocs.content import CHUNK_SIZE, FileContent
from phantomdocs.identity import content_hash, doc_version_mac
from phantomdocs.storage import (
    GdriveBackend,
    LocalBackend,
    StorageError,
    _run_checked,
    read_location,
    read_reference,
)


class BoundedReader(io.BytesIO):
    def read(self, size=-1):
        assert 0 < size <= CHUNK_SIZE
        return super().read(size)


@pytest.mark.parametrize(
    "payload", [b"", b"x" * (CHUNK_SIZE * 2 + 17)], ids=["empty", "multi-chunk"]
)
def test_snapshot_bounded_reads_and_identity(payload, tmp_path):
    with FileContent.from_stream(BoundedReader(payload)) as data:
        assert len(data) == len(payload)
        assert content_hash(data) == content_hash(payload)
        for previous in (None, "b" * 64):
            assert doc_version_mac("a" * 64, previous, "doc", data) == doc_version_mac(
                "a" * 64, previous, "doc", payload
            )
        store = LocalBackend(str(tmp_path))
        store.put(content_hash(data), data)
        with store.get(content_hash(data), streaming=True) as restored:
            assert content_hash(restored) == content_hash(payload)
    assert data.file.closed


def test_large_reference_local_and_drive_memory(tmp_path, monkeypatch):
    source = tmp_path / "large.bin"
    chunk = b"x" * CHUNK_SIZE
    with source.open("wb") as output:
        for _ in range(24):
            output.write(chunk)
    expected = hashlib.sha256(chunk * 24).hexdigest()
    remote = tmp_path / "remote.bin"

    def workspace(args, **kwargs):
        if "drive-upload" in args:
            shutil.copyfile(args[args.index("drive-upload") + 1], remote)
            return mock.Mock(returncode=0, stdout="file-id", stderr="")
        assert "download" in args
        shutil.copyfile(remote, args[-1])
        return mock.Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("phantomdocs.storage._run_checked", workspace)
    monkeypatch.setattr("phantomdocs.storage.shutil.which", lambda value: value)
    tracemalloc.start()
    try:
        data, _location = read_reference(str(source), streaming=True)
        with data:
            assert content_hash(data) == expected
            LocalBackend(str(tmp_path)).put(expected, data)
            assert GdriveBackend().put(expected, data) == "file-id"
            # The captured input remains stable if the original is changed.
            source.write_bytes(b"changed")
            assert content_hash(data) == expected
        with read_location(
            {"backend": "gdrive", "ref": "file-id"},
            expected,
            root=str(tmp_path),
            streaming=True,
        ) as downloaded:
            assert len(downloaded) == CHUNK_SIZE * 24
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * CHUNK_SIZE


def test_subprocess_streams_both_directions(tmp_path):
    payload = b"test data" * 100000
    destination = tmp_path / "uploaded.bin"
    with FileContent.from_stream(BoundedReader(payload)) as source:
        proc = _run_checked(
            [
                sys.executable,
                "-c",
                "import shutil,sys; f=open(sys.argv[1],'wb'); shutil.copyfileobj(sys.stdin.buffer,f); f.close()",
                str(destination),
            ],
            stdin=source,
        )
        assert proc.returncode == 0
    with FileContent() as output:
        proc = _run_checked(
            [
                sys.executable,
                "-c",
                "import shutil,sys; f=open(sys.argv[1],'rb'); shutil.copyfileobj(f,sys.stdout.buffer)",
                str(destination),
            ],
            output=output,
        )
        assert proc.returncode == 0
        assert content_hash(output) == content_hash(payload)


def test_corrupt_stream_is_closed(tmp_path, monkeypatch):
    snapshot = FileContent.from_stream(io.BytesIO(b"wrong bytes"))
    monkeypatch.setattr(
        "phantomdocs.storage.read_reference", lambda *a, **k: (snapshot, {})
    )
    with pytest.raises(StorageError, match="content hash mismatch"):
        read_location(
            {"backend": "file", "ref": "unused"},
            "a" * 64,
            root=str(tmp_path),
            streaming=True,
        )
    assert snapshot.file.closed


def test_failed_snapshot_copy_closes_temp(monkeypatch):
    snapshot = FileContent()
    monkeypatch.setattr(
        "phantomdocs.content.tempfile.TemporaryFile", lambda **kw: snapshot.file
    )
    with (
        mock.patch(
            "phantomdocs.content.shutil.copyfileobj", side_effect=OSError("disk full")
        ),
        pytest.raises(OSError, match="disk full"),
    ):
        FileContent.from_stream(io.BytesIO(b"data"))
    assert snapshot.file.closed
