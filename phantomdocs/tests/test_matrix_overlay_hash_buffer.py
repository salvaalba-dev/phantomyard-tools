"""Shared hash buffer coverage and fail-closed inventory verification."""

import copy
import json
import os
import runpy
import struct
import sys
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="disposable Linux root filesystem required",
)
SOURCE = Path(__file__).resolve().parents[1] / "contrib/matrix-overlay/bootstrap.py"


@pytest.fixture
def tree():
    loaded = runpy.run_path(str(SOURCE), run_name="shared_buffer_test")
    ns = loaded["inventory"].__globals__
    with tempfile.TemporaryDirectory(prefix="pd-hash-buffer-", dir="/var/lib") as tmp:
        root = Path(tmp)
        site = root / "site"
        site.mkdir()
        for index in range(140):
            (site / f"{index:03}.py").write_bytes(bytes([index % 251]) * (index + 1))
        data = root / "data"
        data.mkdir()
        (data / "payload.bin").write_bytes(b"linked package data")
        (site / "linked").symlink_to("../data", target_is_directory=True)
        (site / "disabled.pth").write_text("import sys; sys.exit(99)\n")
        yield ns, root, site


def capture(ns, site, approved=None):
    return ns["inventory"]((site,), (), (), approved=approved)


def test_shared_buffer_matches_independent_file_hashes(tree, monkeypatch):
    ns, _, site = tree
    shared, counts = capture(ns, site)
    assert counts["hashed"] == 142 and counts["reused"] == 0
    original = ns["file_hash"]
    observed = []

    def independent(path, stamp, buffer, metadata, descriptor=None):
        observed.append(buffer)
        digest = original(path, stamp)
        metadata["acl"] = ns["acl_metadata"](path)
        return digest

    monkeypatch.setitem(ns, "file_hash", independent)
    reference, independent_counts = capture(ns, site)
    assert shared == reference and counts == independent_counts
    assert len(observed) == 142 and all(buffer is observed[0] for buffer in observed)


def test_warm_cache_needs_no_hash(tree, monkeypatch):
    ns, _, site = tree
    approved, _ = capture(ns, site)
    monkeypatch.setitem(ns, "file_hash", lambda *args: pytest.fail("unexpected rehash"))
    actual, counts = capture(ns, site, approved)
    assert actual == approved
    assert counts["hashed"] == 0 and counts["reused"] == len(approved["stamps"])


@pytest.mark.parametrize("replacement", ["symlink", "fifo", "changed"])
def test_descriptor_replacement_between_stat_and_open_is_refused(
    tree, monkeypatch, replacement
):
    ns, root, site = tree
    original = ns["file_hash"]

    def replace(path, stamp, buffer, metadata, descriptor=None):
        if Path(path).name == "000.py":
            if replacement == "changed":
                Path(path).write_bytes(b"changed")
            else:
                Path(path).unlink()
                if replacement == "fifo":
                    os.mkfifo(path, 0o600)
                else:
                    Path(path).symlink_to(root / "data/payload.bin")
        return original(path, stamp, buffer, metadata, descriptor)

    monkeypatch.setitem(ns, "file_hash", replace)
    with pytest.raises((ValueError, OSError)):
        capture(ns, site)


@pytest.mark.parametrize("drift", ["bytes", "added", "removed", "acl", "link"])
def test_full_rehash_reports_dependency_and_metadata_drift(tree, drift):
    ns, root, site = tree
    approved, _ = capture(ns, site)
    approved = copy.deepcopy(approved)
    approved["stamps"] = {}
    manifest = root / "approved.json"
    manifest.write_text(json.dumps(approved))
    manifest.chmod(0o600)
    if drift == "bytes":
        (site / "000.py").write_bytes(b"different")
    elif drift == "added":
        (site / "added.py").write_bytes(b"unapproved")
    elif drift == "removed":
        (site / "000.py").unlink()
    elif drift == "acl":
        acl = struct.pack("<I", 2) + b"".join(
            struct.pack("<HHI", tag, perm, uid)
            for tag, perm, uid in (
                (1, 6, 0xFFFFFFFF),
                (2, 4, 65534),
                (4, 4, 0xFFFFFFFF),
                (16, 4, 0xFFFFFFFF),
                (32, 4, 0xFFFFFFFF),
            )
        )
        os.setxattr(site / "000.py", "system.posix_acl_access", acl)
    else:
        (site / "linked").unlink()
        other = root / "other"
        other.mkdir()
        (other / "resource").write_bytes(b"other")
        (site / "linked").symlink_to("../other", target_is_directory=True)
    result = ns["verify_manifest"](manifest, (site,), (), (), report=True)
    assert any(result[key] for key in ("added_paths", "removed_paths", "changed_paths"))


@pytest.mark.parametrize("size", [0, 1, 8191, 8192, 262143, 262144, 262145, 1048607])
def test_hash_boundaries_and_reused_buffer_match_sha256(tree, size):
    import hashlib

    ns, root, _ = tree
    path = root / "boundary.bin"
    data = bytes(range(251)) * (size // 251) + bytes(range(size % 251))
    path.write_bytes(data)
    expected = ns["stamp"](path.stat())
    buffer = bytearray(b"x" * (256 * 1024))
    assert ns["file_hash"](path, expected, buffer) == hashlib.sha256(data).hexdigest()
    # Reuse dirty scratch space for an unrelated shorter file.
    path.write_bytes(b"tail")
    assert (
        ns["file_hash"](path, ns["stamp"](path.stat()), buffer)
        == hashlib.sha256(b"tail").hexdigest()
    )


@pytest.mark.parametrize("mutation", ["grow", "truncate", "same-size"])
def test_mutation_during_hash_is_refused(tree, monkeypatch, mutation):
    import hashlib

    ns, root, _ = tree
    path = root / "mutated.bin"
    path.write_bytes(b"original")
    expected = ns["stamp"](path.stat())
    real_sha256 = hashlib.sha256

    class MutatingDigest:
        def __init__(self):
            self.digest = real_sha256()

        def update(self, data):
            self.digest.update(data)
            before = path.stat()
            path.write_bytes(
                {
                    "grow": b"longer-than-original",
                    "truncate": b"x",
                    "same-size": b"modified",
                }[mutation]
            )
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))

        def hexdigest(self):
            return self.digest.hexdigest()

    monkeypatch.setattr(hashlib, "sha256", MutatingDigest)
    with pytest.raises(ValueError, match="runtime entry changed"):
        ns["file_hash"](path, expected, bytearray(262144))


@pytest.mark.parametrize("fault", [None, "would-block", "permission"])
def test_short_reads_require_eof_and_read_failures_propagate(tree, monkeypatch, fault):
    import hashlib

    ns, root, _ = tree
    path = root / "short.bin"
    data = bytes(range(251)) * 10
    path.write_bytes(data)
    expected = ns["stamp"](path.stat())
    original = os.fdopen
    eof = []

    class ShortReads:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def readinto(self, buffer):
            if fault == "would-block":
                return None
            if fault == "permission":
                raise PermissionError("synthetic read refusal")
            count = self.stream.readinto(memoryview(buffer)[:17])
            if count == 0:
                eof.append(True)
            return count

    monkeypatch.setattr(
        os, "fdopen", lambda *args, **kwargs: ShortReads(original(*args, **kwargs))
    )
    if fault:
        with pytest.raises(
            BlockingIOError if fault == "would-block" else PermissionError
        ):
            ns["file_hash"](path, expected, bytearray(262144))
    else:
        assert (
            ns["file_hash"](path, expected, bytearray(262144))
            == hashlib.sha256(data).hexdigest()
        )
        assert eof == [True]


def test_both_acls_are_read_from_the_verified_descriptor(tree, monkeypatch):
    ns, _, site = tree
    original = os.getxattr
    reads = []

    def observed(path, name, **kwargs):
        if isinstance(path, int):
            assert kwargs == {}
            reads.append((os.fstat(path).st_ino, name))
        else:
            assert kwargs == {"follow_symlinks": False}
        return original(path, name, **kwargs)

    monkeypatch.setattr(os, "getxattr", observed)
    actual, counts = capture(ns, site)
    assert counts["hashed"] == 142 and len(reads) == 284
    for path in actual["stamps"]:
        assert (Path(path).stat().st_ino, "system.posix_acl_access") in reads
        assert (Path(path).stat().st_ino, "system.posix_acl_default") in reads


@pytest.mark.parametrize("kind", ["ENODATA", "ENOTSUP", "EACCES", "EIO"])
def test_descriptor_acl_errors_keep_existing_fail_closed_rules(tree, monkeypatch, kind):
    import errno

    ns, root, _ = tree
    path = root / "acl-error.bin"
    path.write_bytes(b"protected")
    before = ns["stamp"](path.stat())
    result = {}

    def refusal(descriptor, name):
        assert isinstance(descriptor, int)
        raise OSError(getattr(errno, kind), "synthetic xattr result")

    monkeypatch.setattr(os, "getxattr", refusal)
    if kind in {"ENODATA", "ENOTSUP"}:
        ns["file_hash"](path, before, bytearray(262144), result)
        assert result["acl"] == {}
    else:
        with pytest.raises(OSError) as error:
            ns["file_hash"](path, before, bytearray(262144), result)
        assert error.value.errno == getattr(errno, kind)


def test_metadata_change_during_acl_read_is_refused(tree, monkeypatch):
    ns, root, _ = tree
    path = root / "acl-race.bin"
    path.write_bytes(b"protected")
    before = path.stat()
    original = ns["acl_metadata"]

    def mutate(descriptor):
        assert isinstance(descriptor, int)
        result = original(descriptor)
        os.utime(descriptor, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
        return result

    monkeypatch.setitem(ns, "acl_metadata", mutate)
    with pytest.raises(ValueError, match="runtime entry changed"):
        ns["file_hash"](path, ns["stamp"](before), bytearray(262144), {})


@pytest.mark.parametrize("failure", [None, "hash", "advice"])
def test_prefetch_has_at_most_eight_descriptors_and_closes_on_failure(
    tree, monkeypatch, failure
):
    import errno

    ns, _, site = tree
    real_open, real_close, real_advice = os.open, os.close, os.posix_fadvise
    active = set()
    maximum = 0

    def opened(*args, **kwargs):
        nonlocal maximum
        fd = real_open(*args, **kwargs)
        active.add(fd)
        maximum = max(maximum, len(active))
        return fd

    def closed(fd):
        real_close(fd)
        active.remove(fd)

    def advised(*args):
        if failure == "advice":
            raise OSError(errno.EIO, "synthetic advice error")
        return real_advice(*args)

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "close", closed)
    monkeypatch.setattr(os, "posix_fadvise", advised)
    if failure == "hash":

        def refuse(*args):
            raise ValueError("synthetic hash refusal")

        monkeypatch.setitem(ns, "file_hash", refuse)
    if failure:
        with pytest.raises((ValueError, OSError)):
            capture(ns, site)
    else:
        actual, counts = capture(ns, site)
        assert counts["hashed"] == 142 and len(actual["stamps"]) == 142
    assert active == set() and maximum <= 8
    if failure != "advice":
        assert maximum == 8


def test_unsupported_prefetch_hint_preserves_complete_inventory(tree, monkeypatch):
    import errno

    ns, _, site = tree
    expected, counts = capture(ns, site)

    def unsupported(*args):
        raise OSError(errno.ENOTSUP, "no advisory support")

    monkeypatch.setattr(os, "posix_fadvise", unsupported)
    actual, after_counts = capture(ns, site)
    assert actual == expected and counts == after_counts
