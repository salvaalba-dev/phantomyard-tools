"""Actual protected credentials, persona paths and locked/fsynced JSONL; no sends."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from phantomdocs import notify_adapter as adapter

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="Linux root with synthetic protected paths required",
)


@pytest.fixture
def root():
    with tempfile.TemporaryDirectory(
        prefix="notify-adapter-", dir="/var/lib"
    ) as directory:
        yield Path(directory)


def test_real_resolution_requires_selected_persona_to_exist_and_credentials_stay_0600(
    root,
):
    personas = root / "personas"
    personas.mkdir()
    (personas / "only").mkdir()
    runtime = {"data_dir": str(root), "config_path": str(root / "global.toml")}
    assert adapter.resolve(runtime, environ={})[0] == "only"
    (root / "state.json").write_text('{"default_persona":"missing"}')
    with pytest.raises(FileNotFoundError):
        adapter.resolve(runtime, environ={})
    assert adapter.resolve(runtime, explicit="only", environ={})[0] == "only"
    credentials = personas / "only" / "config.toml"
    credentials.write_text('[channels.telegram]\ntoken="synthetic"\n')
    credentials.chmod(0o640)
    with pytest.raises(ValueError):
        adapter.read_file(credentials, 0, private=True)
    assert credentials.stat().st_mode & 0o777 == 0o640  # refuses; never repairs access


def test_actual_jsonl_concurrency_preserves_rows_and_refuses_torn_tail(root):
    ledger = root / "sends.jsonl"
    errors = []

    def append(i):
        try:
            adapter.append_ledger(
                ledger, {"attempt_id": str(i), "status": "attempting"}
            )
        except (OSError, ValueError) as error:
            errors.append(error)

    threads = [threading.Thread(target=append, args=(i,)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert not errors and all(not t.is_alive() for t in threads)
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert len(rows) == 20 and len({r["attempt_id"] for r in rows}) == 20
    assert ledger.stat().st_mode & 0o777 == 0o600
    with ledger.open("ab") as stream:
        stream.write(b'{"torn":')
    before = ledger.read_bytes()
    with pytest.raises(ValueError, match="torn"):
        adapter.append_ledger(ledger, {"status": "attempting"})
    assert ledger.read_bytes() == before


def test_ledger_and_credentials_symlinks_are_refused(root):
    original = root / "original"
    original.write_text("preserve")
    original.chmod(0o600)
    link = root / "link"
    link.symlink_to(original)
    with pytest.raises(OSError):
        adapter.read_file(link, 0, private=True)
    with pytest.raises(OSError):
        adapter.append_ledger(link, {"status": "attempting"})
    assert original.read_text() == "preserve"


def test_selected_persona_owner_is_resolved_inside_a_root_controlled_namespace(root):
    personas = root / "personas"
    personas.mkdir()
    selected = personas / "example"
    selected.mkdir()
    os.chown(selected, 65534, 65534)
    name, path, owner = adapter.resolve(
        {"data_dir": str(root), "config_path": str(root / "missing.toml")},
        explicit="example",
        environ={},
    )
    assert (name, path, owner) == ("example", selected, 65534)


@pytest.fixture
def root_profile(root):
    # Fresh fixtures only: no installed account, directory or access is changed.
    root.chmod(0o711)
    code = root / "code"
    code.mkdir(mode=0o755)
    shutil.copyfile(adapter.__file__, code / "notify_adapter.py")
    config_dir = root / "config"
    config_dir.mkdir(mode=0o750)
    os.chown(config_dir, 0, 65534)
    profile = config_dir / "runtime.json"
    profile.write_text('{"profile":"synthetic-root-controlled"}')
    os.chown(profile, 0, 65534)
    profile.chmod(0o640)
    return code, profile


def read_profile_as_service_user(code, profile, *, extra_groups=()):
    return subprocess.run(
        [
            "/usr/bin/python3",
            "-B",
            "-c",
            "import json,sys; from notify_adapter import read_runtime_config; print(json.dumps(read_runtime_config(sys.argv[1])))",
            str(profile),
        ],
        cwd=code,
        env={"PYTHONPATH": str(code), "PATH": "/usr/bin:/bin"},
        user=65534,
        group=65534,
        extra_groups=list(extra_groups),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_unprivileged_primary_group_reads_root_owned_0640_profile_without_mutation(
    root_profile,
):
    code, profile = root_profile
    before = profile.stat()
    result = read_profile_as_service_user(code, profile)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"profile": "synthetic-root-controlled"}
    after = profile.stat()
    assert (
        after.st_uid,
        after.st_gid,
        after.st_mode,
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) == (
        before.st_uid,
        before.st_gid,
        before.st_mode,
        before.st_ino,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o666, 0o4640])
def test_runtime_profile_refuses_public_or_writable_or_special_modes(
    root_profile, mode
):
    code, profile = root_profile
    profile.chmod(mode)
    before = profile.stat()
    result = read_profile_as_service_user(code, profile)
    assert result.returncode != 0
    assert "unprotected root-owned runtime configuration" in result.stderr
    assert profile.stat().st_mode == before.st_mode


def test_runtime_profile_refuses_nonroot_file_owner(root_profile):
    code, profile = root_profile
    os.chown(profile, 65534, 65534)
    result = read_profile_as_service_user(code, profile)
    assert result.returncode != 0
    assert "unprotected root-owned runtime configuration" in result.stderr


def test_runtime_profile_refuses_user_owned_parent_even_when_file_is_root_owned(
    root_profile,
):
    code, profile = root_profile
    os.chown(profile.parent, 65534, 65534)
    result = read_profile_as_service_user(code, profile)
    assert result.returncode != 0 and "unprotected directory" in result.stderr


def test_runtime_profile_refuses_group_writable_root_parent(root_profile):
    code, profile = root_profile
    profile.parent.chmod(0o770)
    result = read_profile_as_service_user(code, profile)
    assert result.returncode != 0 and "unprotected directory" in result.stderr


def test_runtime_profile_refuses_supplementary_group_access_as_a_primary_group_substitute(
    root_profile,
):
    code, profile = root_profile
    os.chown(profile, 0, 65533)
    result = read_profile_as_service_user(code, profile, extra_groups=(65533,))
    assert result.returncode != 0
    assert "unprotected root-owned runtime configuration" in result.stderr


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_runtime_profile_refuses_symlink_and_hardlink_aliases(root_profile, link_kind):
    code, profile = root_profile
    alias = profile.with_name("alias.json")
    if link_kind == "symlink":
        alias.symlink_to(profile)
    else:
        os.link(profile, alias)
    result = read_profile_as_service_user(code, alias)
    assert result.returncode != 0


def test_runtime_profile_refuses_oversized_content(root_profile):
    code, profile = root_profile
    profile.write_bytes(b" " * (adapter.MAX_BYTES + 1))
    result = read_profile_as_service_user(code, profile)
    assert result.returncode != 0 and "exceeded limit" in result.stderr


def test_runtime_profile_root_operator_can_still_read_root_owned_0600(root):
    profile = root / "root-only.json"
    profile.write_text('{"operator":"root"}')
    profile.chmod(0o600)
    assert adapter.read_runtime_config(profile) == {"operator": "root"}


def test_runtime_profile_refuses_atomic_replacement_during_read(root, monkeypatch):
    profile = root / "runtime.json"
    profile.write_text('{"revision":"before"}')
    profile.chmod(0o600)
    replacement = root / "replacement.json"
    replacement.write_text('{"revision":"after"}')
    replacement.chmod(0o600)
    read = adapter.os.read

    def replaced(fd, length):
        raw = read(fd, length)
        os.replace(replacement, profile)
        return raw

    monkeypatch.setattr(adapter.os, "read", replaced)
    with pytest.raises(ValueError, match="changed"):
        adapter.read_runtime_config(profile)


def test_group_readable_tokens_and_ledger_remain_refused(root):
    token = root / "config.toml"
    token.write_text('[channels.telegram]\ntoken="synthetic"\n')
    token.chmod(0o640)
    with pytest.raises(ValueError):
        adapter.read_file(token, 0, private=True)
    ledger = root / "ledger.jsonl"
    ledger.touch(mode=0o640)
    with pytest.raises(ValueError):
        adapter.append_ledger(ledger, {"status": "attempting"})
    assert token.stat().st_mode & 0o777 == 0o640
    assert ledger.stat().st_mode & 0o777 == 0o640
    assert ledger.read_bytes() == b""
