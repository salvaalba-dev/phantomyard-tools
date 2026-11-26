"""Inventory semantics on user-owned fixtures, without root or systemd.

Only the ownership/protection policy is replaced in the inventory fixture.
Real reads, stamps, hashes, reuse and manifest comparisons remain exercised.
Privileged tests separately cover real protected ownership and ACL enforcement.
"""

import copy
import errno
import hashlib
import json
import os
import runpy
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux bootstrap")
SOURCE = Path(__file__).resolve().parents[1] / "contrib/matrix-overlay/bootstrap.py"


@pytest.fixture
def bootstrap():
    return runpy.run_path(str(SOURCE), run_name="inventory_unit_test")


@pytest.fixture
def runtime(bootstrap, tmp_path, monkeypatch):
    ns = bootstrap["inventory"].__globals__
    monkeypatch.setitem(ns, "require_protected", lambda *_args: None)
    site = tmp_path / "site"
    site.mkdir()
    (site / "module.py").write_bytes(b"VALUE = 1\n")
    (site / "data.bin").write_bytes(bytes(range(251)))
    return ns, site, tmp_path


def capture(ns, site, approved=None):
    return ns["inventory"]((site,), (), (), approved=approved)


def test_capture_hashes_every_file_without_importing_it(runtime):
    ns, site, _ = runtime
    actual, counts = capture(ns, site)
    assert counts == {"hashed": 2, "reused": 0, "rehashed_paths": []}
    for path in site.iterdir():
        assert (
            actual["entries"][str(path)]["sha256"]
            == hashlib.sha256(path.read_bytes()).hexdigest()
        )
    assert set(actual["stamps"]) == {str(path) for path in site.iterdir()}


def test_unchanged_stamps_reuse_hashes(runtime, monkeypatch):
    ns, site, _ = runtime
    approved, _ = capture(ns, site)
    monkeypatch.setitem(ns, "file_hash", lambda *_args: pytest.fail("rehash"))
    actual, counts = capture(ns, site, approved)
    assert actual == approved
    assert counts == {"hashed": 0, "reused": 2, "rehashed_paths": []}


def test_empty_stamps_force_full_hash_without_changing_entries(runtime):
    ns, site, _ = runtime
    approved, _ = capture(ns, site)
    forced = copy.deepcopy(approved)
    forced["stamps"] = {}
    actual, counts = capture(ns, site, forced)
    assert actual == approved
    assert counts["hashed"] == 2 and counts["reused"] == 0
    assert counts["rehashed_paths"] == sorted(approved["stamps"])


@pytest.mark.parametrize("drift", ["bytes", "added", "removed", "mode"])
def test_manifest_refuses_drift_before_launcher(runtime, drift):
    ns, site, root = runtime
    approved, _ = capture(ns, site)
    manifest = root / "approved.json"
    manifest.write_text(json.dumps(approved))
    path = site / "module.py"
    if drift == "bytes":
        path.write_bytes(b"raise AssertionError('must never execute')\n")
    elif drift == "added":
        (site / "extra.py").write_bytes(b"unapproved")
    elif drift == "removed":
        path.unlink()
    else:
        path.chmod(0o400)
    report = ns["verify_manifest"](manifest, (site,), (), (), report=True)
    assert any(report[key] for key in ("added_paths", "removed_paths", "changed_paths"))
    with pytest.raises(ValueError, match="differs from approved inventory"):
        ns["verify_manifest"](manifest, (site,), (), ())


def test_stamp_change_rehashes_identical_content(runtime):
    ns, site, _ = runtime
    approved, _ = capture(ns, site)
    path = site / "module.py"
    before = path.stat()
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    actual, counts = capture(ns, site, approved)
    assert actual["entries"] == approved["entries"]
    assert counts == {"hashed": 1, "reused": 1, "rehashed_paths": [str(path)]}


@pytest.mark.parametrize("bad", [[], {"version": 2, "entries": {}, "stamps": []}])
def test_malformed_manifest_fails_closed(runtime, bad):
    ns, site, root = runtime
    manifest = root / "bad.json"
    manifest.write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="invalid runtime manifest format"):
        ns["verify_manifest"](manifest, (site,), (), ())


def test_hash_failure_is_not_converted_to_success(runtime, monkeypatch):
    ns, site, _ = runtime

    def fail(*_args):
        raise OSError(errno.EIO, "synthetic read failure")

    monkeypatch.setitem(ns, "file_hash", fail)
    with pytest.raises(OSError) as result:
        capture(ns, site)
    assert result.value.errno == errno.EIO


@pytest.mark.parametrize("error", [errno.ENOSYS, errno.ENOTSUP])
def test_unsupported_advice_preserves_full_hashing(runtime, monkeypatch, error):
    ns, site, _ = runtime
    expected, _ = capture(ns, site)

    def unsupported(*_args):
        raise OSError(error, "synthetic unavailable advisory hint")

    monkeypatch.setattr(os, "posix_fadvise", unsupported)
    actual, counts = capture(ns, site)
    assert actual == expected and counts["hashed"] == 2 and counts["reused"] == 0


@pytest.mark.parametrize("uid,mode", [(1234, 0o644), (0, 0o664), (0, 0o646)])
def test_real_protection_policy_refuses_unsafe_metadata(bootstrap, uid, mode):
    metadata = SimpleNamespace(st_uid=uid, st_mode=stat.S_IFREG | mode)
    with pytest.raises(ValueError, match="unprotected runtime entry"):
        bootstrap["require_protected"]("synthetic", metadata)


def test_real_protection_policy_accepts_root_read_only_metadata(bootstrap):
    metadata = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644)
    bootstrap["require_protected"]("synthetic", metadata)
