"""Local receipt custody is an explicit POSIX trust boundary."""

import os

import pytest

from phantomdocs.workflow_receipt_store import (
    MAX_RECEIPT_BYTES,
    read_receipt,
    trusted_receipt_directory,
)
from phantomdocs.workflows import WorkflowError

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="Requires POSIX directory handles"
)


@pytest.fixture
def private(tmp_path):
    tmp_path.chmod(0o700)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield tmp_path, fd
    finally:
        os.close(fd)


def write(private, text, mode=0o600):
    path, _ = private
    item = path / "receipt.json"
    item.write_text(text, encoding="utf-8")
    item.chmod(mode)
    return item


def test_reads_private_receipt(private):
    write(private, '{"schema":"example","data":{"id":1}}')
    assert read_receipt(private[1], "receipt.json")["data"] == {"id": 1}


def test_opens_validated_full_path(private):
    write(private, '{"schema":"example"}')
    with trusted_receipt_directory(str(private[0])) as fd:
        assert read_receipt(fd, "receipt.json")["schema"] == "example"


def test_rejects_symlinked_directory_component(private):
    target = private[0] / "actual"
    target.mkdir(mode=0o700)
    alias = private[0] / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(WorkflowError), trusted_receipt_directory(str(alias)):
        pass


def test_rejects_writable_nonsticky_ancestor(private):
    parent = private[0] / "shared"
    parent.mkdir(mode=0o777)
    parent.chmod(0o777)
    child = parent / "private"
    child.mkdir(mode=0o700)
    with (
        pytest.raises(WorkflowError, match="ancestor"),
        trusted_receipt_directory(str(child)),
    ):
        pass


@pytest.mark.parametrize("path", ["relative", "/tmp/../tmp", "/tmp//unsafe"])
def test_rejects_invalid_directory_path(path):
    with pytest.raises(WorkflowError), trusted_receipt_directory(path):
        pass


@pytest.mark.parametrize(
    "payload",
    ['{"a":1,"a":2}', '{"a":NaN}', "[]", "x" * (MAX_RECEIPT_BYTES + 1)],
    ids=["duplicate", "nonfinite", "not-object", "oversized"],
)
def test_refuses_invalid_receipts(private, payload):
    write(private, payload)
    with pytest.raises(WorkflowError):
        read_receipt(private[1], "receipt.json")


def test_refuses_shared_file_or_directory(private):
    item = write(private, "{}", 0o640)
    with pytest.raises(WorkflowError):
        read_receipt(private[1], "receipt.json")
    item.chmod(0o600)
    private[0].chmod(0o750)
    with pytest.raises(WorkflowError):
        read_receipt(private[1], "receipt.json")


def test_refuses_symlink_and_hardlink(private):
    path, fd = private
    item = write(private, "{}")
    (path / "link.json").symlink_to(item)
    with pytest.raises(WorkflowError):
        read_receipt(fd, "link.json")
    os.link(item, path / "hardlink.json")
    with pytest.raises(WorkflowError):
        read_receipt(fd, "receipt.json")


@pytest.mark.parametrize("name", ["../receipt.json", "", ".", "sub/receipt.json"])
def test_refuses_paths(private, name):
    with pytest.raises(WorkflowError):
        read_receipt(private[1], name)
