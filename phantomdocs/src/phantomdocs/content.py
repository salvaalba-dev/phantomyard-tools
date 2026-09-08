"""Disk-backed snapshots for bounded-memory document processing."""

import hashlib
import io
import shutil
import tempfile

CHUNK_SIZE = 1024 * 1024


class FileContent:
    """An owned temporary file; callers close it after processing the document.

    Snapshotting keeps hashing and uploading on the same bytes even when the
    original file changes. Memory use stays bounded; disk use scales with size.
    """

    def __init__(self):
        self.file = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115 -- owned by this context manager

    @classmethod
    def from_stream(cls, source):
        result = cls()
        try:
            shutil.copyfileobj(source, result.file, CHUNK_SIZE)
            result.file.seek(0)
            return result
        except BaseException:
            result.close()
            raise

    def __len__(self):
        position = self.file.tell()
        size = self.file.seek(0, io.SEEK_END)
        self.file.seek(position)
        return size

    def digest(self):
        self.file.seek(0)
        digest = hashlib.sha256()
        while chunk := self.file.read(CHUNK_SIZE):
            digest.update(chunk)
        self.file.seek(0)
        return digest.digest()

    def copy_to(self, destination):
        self.file.seek(0)
        shutil.copyfileobj(self.file, destination, CHUNK_SIZE)
        self.file.seek(0)

    def close(self):
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def write_content(destination, content):
    if isinstance(content, FileContent):
        content.copy_to(destination)
    else:
        destination.write(content)
