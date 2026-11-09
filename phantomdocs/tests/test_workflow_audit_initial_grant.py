import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from phantomdocs.workflow_audit_initial_grant import create_initial_grant


@pytest.mark.skipif(
    os.name != "posix" or os.getuid() == 0, reason="unprivileged POSIX owner"
)
def test_initial_grant_is_atomic_and_never_overwrites_policy():
    with tempfile.TemporaryDirectory(prefix="review-grant-", dir=Path.home()) as path:

        def create():
            try:
                create_initial_grant(
                    path, "review-server", lifetime_seconds=60, now=1000
                )
                return "created"
            except FileExistsError:
                return "existing"

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(lambda _: create(), range(2))) == [
                "created",
                "existing",
            ]
        policy = Path(path) / "security-policy.json"
        before = policy.read_bytes()
        doc = json.loads(before)
        assert doc["enabled"] is True and len(doc["grants"]) == 1
        assert doc["grants"][0]["expiresAt"] == 1060000
        assert doc["grants"][0]["arguments"] == {}
        assert policy.stat().st_mode & 0o077 == 0
        with pytest.raises(FileExistsError):
            create_initial_grant(path, "review-server", lifetime_seconds=60, now=1000)
        assert policy.read_bytes() == before
        assert list(Path(path).iterdir()) == [policy]


@pytest.mark.skipif(
    os.name != "posix" or os.getuid() == 0, reason="unprivileged POSIX owner"
)
def test_invalid_authority_is_rejected_before_policy_creation():
    with tempfile.TemporaryDirectory(prefix="review-grant-", dir=Path.home()) as path:
        for server, lifetime in [
            ("bad server", 60),
            ("review", 0),
            ("review", 1801),
            ("review", True),
        ]:
            with pytest.raises(ValueError):
                create_initial_grant(path, server, lifetime_seconds=lifetime)
        assert not list(Path(path).iterdir())
