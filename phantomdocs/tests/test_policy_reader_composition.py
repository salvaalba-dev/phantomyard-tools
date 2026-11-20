"""Explicit local integration against the exact reviewed reader candidate."""

import os
import runpy
from pathlib import Path

import pytest

from phantomdocs.view_agent_launcher_patch import patch_launcher
from phantomdocs.view_agent_mixed_patch import patch_launcher as mixed_launcher
from phantomdocs.view_agent_mixed_patch import patch_reader as mixed_reader
from phantomdocs.view_agent_reader_patch import patch_reader
from phantomdocs.view_projection_dynamic_patch import patch_projection_consumer


@pytest.mark.skipif(
    not os.environ.get("PHANTOMVIEW_COMMIT_REFERENCE"),
    reason="explicit viewer candidate required",
)
def test_exact_mixed_reader_and_launcher_keep_the_committed_policy_contract(
    tmp_path, monkeypatch
):
    root = Path(os.environ["PHANTOMVIEW_COMMIT_REFERENCE"])
    assert root.is_absolute()
    monkeypatch.syspath_prepend(str(root))
    launcher = tmp_path / "launcher.py"
    reader = tmp_path / "reader.py"
    launcher.write_bytes(
        patch_projection_consumer(
            "reader_launch.py",
            mixed_launcher(patch_launcher((root / "reader_launch.py").read_bytes())),
        )
    )
    reader.write_bytes(
        patch_projection_consumer(
            "identified_reader.py",
            mixed_reader(patch_reader((root / "identified_reader.py").read_bytes())),
        )
    )
    loader = runpy.run_path(str(launcher))
    loaded_reader = runpy.run_path(str(reader))
    from test_policy_delivery import PolicyDeliveryTests
    from test_reader_launch import example

    config = example() | {
        "schema_version": 2,
        "policy_lock": "/etc/example/policy.lock",
        "agent_actors": [],
        "mixed_agent_signers": {},
    }
    assert loader["validate"](config)["policy_lock"] == config["policy_lock"]
    trial = PolicyDeliveryTests()
    trial.setUp()
    try:
        server = trial.server(loaded_reader["RecipientHandler"])
        assert trial.request(server)[0] == 200
        trial.pending = True
        assert trial.request(server)[0] == 503
        trial.pending = False
        trial.committed["sha256"] = "f" * 64
        assert trial.request(server)[0] == 503
    finally:
        trial.doCleanups()
