"""Actual protected credentials, persona paths and locked/fsynced JSONL; no sends."""

import json
import os
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
