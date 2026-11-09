import os

import pytest

from phantomdocs.workflow_audit_collection import collection_guard


@pytest.mark.skipif(os.name != "posix", reason="POSIX file locks")
def test_failed_collection_blocks_readers_until_a_successful_retry(tmp_path):
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with (
            pytest.raises(FileNotFoundError),
            collection_guard(directory, os.getuid(), writer=False),
        ):
            pass
        with (
            pytest.raises(RuntimeError),
            collection_guard(directory, os.getuid(), writer=True),
        ):
            with (
                pytest.raises(BlockingIOError),
                collection_guard(directory, os.getuid(), writer=False),
            ):
                pass
            raise RuntimeError("collection failed")
        with (
            pytest.raises(ValueError),
            collection_guard(directory, os.getuid(), writer=False),
        ):
            pass
        with collection_guard(directory, os.getuid(), writer=True):
            pass
        with collection_guard(directory, os.getuid(), writer=False):
            pass
    finally:
        os.close(directory)
