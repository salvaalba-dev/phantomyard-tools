"""Exercise interrupted publication through the real matrix authority consumer."""

import hashlib
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from test_guarded_service import org_fixture

from phantomdocs import workflow_policy_publish as publication
from phantomdocs.access import can_write
from phantomdocs.manifest import empty_manifest, save
from phantomdocs.view_matrix_authority import guarded_matrix_authority
from phantomdocs.workflow_policy_guard import PolicyRecoveryRequired, policy_guard
from phantomdocs.workflow_policy_sync import synchronize


def test_shared_lock_cannot_bypass_interrupted_publication():
    with pytest.raises(ValueError, match="exclusive"):  # noqa: SIM117
        with policy_guard("/protected/lock", exclusive=False, recovering=True):
            pytest.fail("shared recovery was allowed")


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux protected paths")
@pytest.mark.parametrize("interrupted_copy", [1, 2])
def test_interrupted_publication_blocks_sync_and_matrix_until_recovery(
    interrupted_copy,
):
    if os.geteuid() != 0:
        pytest.skip("requires root and protected paths")
    with tempfile.TemporaryDirectory(dir="/root") as directory:
        paths = {
            name: str(Path(directory) / name)
            for name in ("source", "destination", "backup", "candidate", "lock")
        }
        policy = org_fixture()
        old = yaml.safe_dump(policy).encode()
        for name in ("source", "destination", "backup"):
            Path(paths[name]).write_bytes(old)
            Path(paths[name]).chmod(0o640)
        policy["actors"][0]["actor_exceptions"] = []
        Path(paths["candidate"]).write_text(yaml.safe_dump(policy))
        Path(paths["lock"]).touch(mode=0o600)
        manifest = str(Path(directory) / "manifest.yaml")
        save(manifest, empty_manifest("synthetic", "docs", "a" * 64))

        def authority():
            return guarded_matrix_authority(
                policy_lock=paths["lock"],
                org_path=paths["destination"],
                native_manifest=manifest,
                reader=lambda *args: None,
            )

        with authority() as (org, _, _):
            assert can_write(org, "project_actor", "category-4-project-a", ["lead"])

        original = publication._synchronize_locked
        calls = 0

        def interrupt(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == interrupted_copy:
                raise OSError("synthetic interruption")
            return original(*args, **kwargs)

        with patch.object(publication, "_synchronize_locked", side_effect=interrupt):  # noqa: SIM117
            with pytest.raises(OSError, match="synthetic interruption"):
                publication.publish(
                    *(
                        paths[name]
                        for name in (
                            "candidate",
                            "source",
                            "destination",
                            "backup",
                            "lock",
                        )
                    ),
                    hashlib.sha256(old).hexdigest(),
                )

        before = {name: Path(path).read_bytes() for name, path in paths.items()}
        marker = Path(paths["lock"] + ".pending")
        pending = marker.read_bytes()
        # A regular sync must not turn an interrupted two-file transaction into
        # an unrecorded third state, even with valid protected input.
        with pytest.raises(PolicyRecoveryRequired):
            synchronize(paths["candidate"], paths["destination"], paths["lock"])
        assert {name: Path(path).read_bytes() for name, path in paths.items()} == before
        assert marker.read_bytes() == pending
        with pytest.raises(PolicyRecoveryRequired):  # noqa: SIM117
            with authority():
                pytest.fail("matrix authority used an interrupted policy")

        publication.recover(paths["source"], paths["destination"], paths["lock"])
        assert not marker.exists()
        assert (
            Path(paths["source"]).read_bytes()
            == Path(paths["destination"]).read_bytes()
        )
        assert Path(paths["backup"]).read_bytes() == old
        for name in ("source", "destination", "backup"):
            assert Path(paths[name]).stat().st_mode & 0o777 == 0o640
        with authority() as (org, _, _):
            assert can_write(
                org, "project_actor", "category-4-project-a", ["lead"]
            ) == (interrupted_copy == 1)
